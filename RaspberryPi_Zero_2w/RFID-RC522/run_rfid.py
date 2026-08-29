#!/usr/bin/env python3

"""
======================================================================
                 RFID-RC522 EXTREME VERBOSE LOGGER
======================================================================

Hardware:
    Raspberry Pi Zero 2 W
    MFRC522 / RC522 RFID reader
    13.56 MHz ISO14443A / MIFARE-compatible cards

WIRING
----------------------------------------------------------------------

    RC522        Raspberry Pi Zero 2 W
    ------------------------------------------------
    VCC      ->  Pin 1   (3.3V)
    GND      ->  Pin 6   (GND)
    RST      ->  Pin 22  (GPIO25)
    MISO     ->  Pin 21  (GPIO9)
    MOSI     ->  Pin 19  (GPIO10)
    SCK      ->  Pin 23  (GPIO11)
    SDA/SS   ->  Pin 24  (GPIO8 / CE0)
    IRQ      ->  Not connected


PURPOSE
----------------------------------------------------------------------

This program is READ-ONLY.

For each detected card it attempts to collect as much information as
the RC522 and installed MFRC522 Python library can provide.

For MIFARE Classic-compatible cards, it attempts to:

    1. Detect the card
    2. Obtain the UID
    3. Obtain the ATQA/request response
    4. Select the card
    5. Record the SAK response
    6. Authenticate sectors using the default Key A
    7. Read all accessible blocks
    8. Display raw HEX data
    9. Display ASCII representation
   10. Record failures
   11. Save everything to a timestamped TXT file

MIFARE Classic 1K layout:

    16 sectors
    4 blocks per sector
    64 blocks total
    16 bytes per block


OUTPUT DIRECTORY
----------------------------------------------------------------------

    scans/

Example:

    scans/
        2026-08-29_03-15-42_001.txt
        2026-08-29_03-16-08_002.txt
        2026-08-29_03-17-21_003.txt

======================================================================
"""

import os
import time
from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import MFRC522


# ======================================================================
# CONFIGURATION
# ======================================================================

SCRIPT_DIRECTORY = os.path.dirname(
    os.path.abspath(__file__)
)

SCAN_DIRECTORY = os.path.join(
    SCRIPT_DIRECTORY,
    "scans"
)

# Default MIFARE Classic factory key.
DEFAULT_KEY = [
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF
]

POLL_DELAY = 0.10

CARD_REMOVAL_CHECK_DELAY = 0.50


# ======================================================================
# DISPLAY HELPERS
# ======================================================================

def separator(character="=", length=78):
    print(character * length)


def section(title):
    print()
    separator("=")
    print(f" {title}")
    separator("=")


def subsection(title):
    print()
    separator("-")
    print(f" {title}")
    separator("-")


# ======================================================================
# DATA FORMATTING
# ======================================================================

def normalise_bytes(data):
    """
    Convert common library return values into a list of integers.
    """

    if data is None:
        return []

    if isinstance(data, int):
        return [data & 0xFF]

    try:
        return [
            int(value) & 0xFF
            for value in data
        ]

    except TypeError:
        return []


def bytes_to_hex(data):

    values = normalise_bytes(data)

    return " ".join(
        f"{value:02X}"
        for value in values
    )


def bytes_to_colon_hex(data):

    values = normalise_bytes(data)

    return ":".join(
        f"{value:02X}"
        for value in values
    )


def bytes_to_binary(data):

    values = normalise_bytes(data)

    return " ".join(
        f"{value:08b}"
        for value in values
    )


def bytes_to_decimal(data):

    values = normalise_bytes(data)

    return " ".join(
        str(value)
        for value in values
    )


def bytes_to_ascii(data):

    values = normalise_bytes(data)

    output = ""

    for value in values:

        if 32 <= value <= 126:
            output += chr(value)

        else:
            output += "."

    return output


def describe_bytes(data):

    values = normalise_bytes(data)

    if not values:
        return "No bytes"

    return (
        f"HEX     : {bytes_to_hex(values)}\n"
        f"DECIMAL : {bytes_to_decimal(values)}\n"
        f"BINARY  : {bytes_to_binary(values)}\n"
        f"ASCII   : {bytes_to_ascii(values)}"
    )


# ======================================================================
# TAG TYPE INFORMATION
# ======================================================================

def describe_request_type(value):

    if value is None:
        return "Unknown"

    try:
        value = int(value)

    except Exception:
        return str(value)

    known = {
        0x04: "PICC_REQIDL / ISO14443A request",
        0x10: "PICC_REQALL / ISO14443A request",
    }

    return (
        f"0x{value:02X} - "
        f"{known.get(value, 'Unknown request response')}"
    )


def describe_sak(sak):

    try:
        sak = int(sak)

    except Exception:
        return "Unknown"

    return (
        f"0x{sak:02X} "
        f"(decimal {sak})"
    )


# ======================================================================
# FILE MANAGEMENT
# ======================================================================

def create_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


def get_next_scan_id():

    create_scan_directory()

    highest_id = 0

    for filename in os.listdir(
        SCAN_DIRECTORY
    ):

        if not filename.endswith(".txt"):
            continue

        try:

            number = int(
                filename
                .rsplit("_", 1)[1]
                .replace(".txt", "")
            )

            highest_id = max(
                highest_id,
                number
            )

        except (
            ValueError,
            IndexError
        ):

            continue

    return highest_id + 1


# ======================================================================
# TERMINAL BLOCK DISPLAY
# ======================================================================

def print_block(
    sector,
    block,
    data,
    status,
    reason=None
):

    print()
    print(
        f"    Sector {sector:02d} | "
        f"Block {block:02d}"
    )

    print(
        "    ----------------------------------------------------------"
    )

    print(
        f"    Status      : {status}"
    )

    if reason:
        print(
            f"    Reason      : {reason}"
        )

    if data is not None:

        values = normalise_bytes(data)

        print(
            f"    Byte count  : {len(values)}"
        )

        print(
            f"    HEX         : "
            f"{bytes_to_hex(values)}"
        )

        print(
            f"    DECIMAL     : "
            f"{bytes_to_decimal(values)}"
        )

        print(
            f"    ASCII       : "
            f"{bytes_to_ascii(values)}"
        )


# ======================================================================
# READ MIFARE CLASSIC 1K
# ======================================================================

def read_mifare_classic(
    reader,
    uid
):

    section(
        "MIFARE CLASSIC 1K MEMORY SCAN"
    )

    print(
        "Attempting to authenticate and read all 16 sectors."
    )

    print(
        "Each sector contains 4 blocks."
    )

    print(
        "Total blocks attempted: 64"
    )

    print()

    print(
        "Authentication key being attempted:"
    )

    print(
        f"    {bytes_to_hex(DEFAULT_KEY)}"
    )

    memory = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    sectors_authenticated = 0


    # --------------------------------------------------------------
    # 16 sectors
    # --------------------------------------------------------------

    for sector in range(16):

        first_block = sector * 4

        trailer_block = first_block + 3


        subsection(
            f"SECTOR {sector:02d}"
        )

        print(
            f"First block       : {first_block}"
        )

        print(
            f"Last block        : {trailer_block}"
        )

        print(
            f"Sector trailer    : Block {trailer_block}"
        )

        print()

        print(
            "Authenticating sector using Key A..."
        )

        print(
            f"Authentication block: {trailer_block}"
        )


        try:

            auth_status = reader.MFRC522_Auth(
                reader.PICC_AUTHENT1A,
                trailer_block,
                DEFAULT_KEY,
                uid
            )

        except Exception as error:

            auth_status = -1

            print(
                f"AUTHENTICATION EXCEPTION: {error}"
            )


        print(
            f"Authentication result: {auth_status}"
        )


        if auth_status != reader.MI_OK:

            authentication_failed += 1

            print(
                "Authentication: FAILED"
            )

            print(
                "Skipping the blocks in this sector."
            )

            for block in range(
                first_block,
                first_block + 4
            ):

                memory.append({

                    "sector": sector,
                    "block": block,
                    "status": "AUTHENTICATION FAILED",
                    "data": None,
                    "reason": (
                        f"Authentication returned "
                        f"{auth_status}"
                    )
                })

            continue


        sectors_authenticated += 1

        print(
            "Authentication: SUCCESS"
        )

        print(
            "Reading blocks..."
        )


        # ----------------------------------------------------------
        # Four blocks in the sector
        # ----------------------------------------------------------

        for block in range(
            first_block,
            first_block + 4
        ):

            print()
            print(
                f"    >>> READ REQUEST"
            )

            print(
                f"    Sector : {sector}"
            )

            print(
                f"    Block  : {block}"
            )

            try:

                data = reader.MFRC522_Read(
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"    EXCEPTION: {error}"
                )


            if data is not None:

                values = normalise_bytes(
                    data
                )

                blocks_read += 1

                memory.append({

                    "sector": sector,
                    "block": block,
                    "status": "READ OK",
                    "data": values,
                    "reason": None

                })


                print_block(
                    sector,
                    block,
                    values,
                    "READ OK"
                )


            else:

                blocks_failed += 1

                memory.append({

                    "sector": sector,
                    "block": block,
                    "status": "READ FAILED",
                    "data": None,
                    "reason": (
                        "MFRC522_Read returned "
                        "None"
                    )

                })


                print_block(
                    sector,
                    block,
                    None,
                    "READ FAILED",
                    "MFRC522_Read returned None"
                )


    # --------------------------------------------------------------
    # Stop authentication
    # --------------------------------------------------------------

    print()

    print(
        "Stopping MIFARE Crypto1 authentication..."
    )

    try:

        reader.MFRC522_StopCrypto1()

        print(
            "Crypto1 authentication stopped."
        )

    except Exception as error:

        print(
            f"Crypto1 stop warning: {error}"
        )


    # --------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------

    section(
        "MEMORY READ SUMMARY"
    )

    print(
        f"Sectors authenticated : "
        f"{sectors_authenticated}/16"
    )

    print(
        f"Authentication failures: "
        f"{authentication_failed}"
    )

    print(
        f"Blocks read successfully: "
        f"{blocks_read}/64"
    )

    print(
        f"Blocks failed           : "
        f"{blocks_failed}"
    )

    print(
        f"Total block records     : "
        f"{len(memory)}"
    )


    return (
        memory,
        blocks_read,
        blocks_failed,
        authentication_failed,
        sectors_authenticated
    )


# ======================================================================
# SAVE SCAN FILE
# ======================================================================

def save_scan(
    scan_id,
    timestamp,
    uid,
    request_type,
    sak,
    selection_result,
    memory,
    blocks_read,
    blocks_failed,
    authentication_failed,
    sectors_authenticated
):

    create_scan_directory()


    filename = (
        f"{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}"
        f"_{scan_id:03d}.txt"
    )


    filepath = os.path.join(
        SCAN_DIRECTORY,
        filename
    )


    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:


        # ==========================================================
        # HEADER
        # ==========================================================

        file.write(
            "=" * 78 + "\n"
        )

        file.write(
            "                    RFID SCAN RECORD\n"
        )

        file.write(
            "=" * 78 + "\n\n"
        )


        # ==========================================================
        # SCAN INFORMATION
        # ==========================================================

        file.write(
            "[SCAN INFORMATION]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )

        file.write(
            f"Scan ID                  : "
            f"{scan_id:03d}\n"
        )

        file.write(
            f"Timestamp                : "
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        )

        file.write(
            f"Reader                   : "
            f"MFRC522 / RC522\n"
        )

        file.write(
            f"Interface                : "
            f"SPI0 CE0\n"
        )

        file.write(
            f"Scan mode                : "
            f"READ ONLY\n"
        )

        file.write(
            f"Scan directory           : "
            f"{SCAN_DIRECTORY}\n"
        )

        file.write("\n")


        # ==========================================================
        # CARD IDENTIFICATION
        # ==========================================================

        file.write(
            "[CARD IDENTIFICATION]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )

        file.write(
            f"UID                      : "
            f"{bytes_to_colon_hex(uid)}\n"
        )

        file.write(
            f"UID HEX                  : "
            f"{bytes_to_hex(uid)}\n"
        )

        file.write(
            f"UID DECIMAL              : "
            f"{bytes_to_decimal(uid)}\n"
        )

        file.write(
            f"UID BINARY               : "
            f"{bytes_to_binary(uid)}\n"
        )

        file.write(
            f"UID ASCII                : "
            f"{bytes_to_ascii(uid)}\n"
        )

        file.write(
            f"UID Length               : "
            f"{len(uid)} bytes\n"
        )

        file.write(
            f"Request / ATQA           : "
            f"{describe_request_type(request_type)}\n"
        )

        file.write(
            f"SAK                      : "
            f"{describe_sak(sak)}\n"
        )

        file.write(
            f"Card selection result    : "
            f"{selection_result}\n"
        )

        file.write("\n")


        # ==========================================================
        # RAW UID
        # ==========================================================

        file.write(
            "[RAW UID DATA]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )

        file.write(
            f"HEX      : "
            f"{bytes_to_hex(uid)}\n"
        )

        file.write(
            f"DECIMAL  : "
            f"{bytes_to_decimal(uid)}\n"
        )

        file.write(
            f"BINARY   : "
            f"{bytes_to_binary(uid)}\n"
        )

        file.write(
            f"ASCII    : "
            f"{bytes_to_ascii(uid)}\n"
        )

        file.write("\n")


        # ==========================================================
        # MEMORY
        # ==========================================================

        file.write(
            "[CARD MEMORY]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )


        current_sector = None


        for entry in memory:

            sector = entry["sector"]


            if sector != current_sector:

                file.write("\n")

                file.write(
                    f"SECTOR {sector:02d}\n"
                )

                file.write(
                    "^" * 78 + "\n"
                )

                current_sector = sector


            block = entry["block"]

            file.write(
                f"\nBlock {block:02d}\n"
            )

            file.write(
                "-" * 30 + "\n"
            )

            file.write(
                f"Status     : "
                f"{entry['status']}\n"
            )


            if entry["reason"]:

                file.write(
                    f"Reason     : "
                    f"{entry['reason']}\n"
                )


            if entry["data"] is not None:

                data = entry["data"]

                file.write(
                    f"Byte count : "
                    f"{len(data)}\n"
                )

                file.write(
                    f"HEX        : "
                    f"{bytes_to_hex(data)}\n"
                )

                file.write(
                    f"DECIMAL    : "
                    f"{bytes_to_decimal(data)}\n"
                )

                file.write(
                    f"BINARY     : "
                    f"{bytes_to_binary(data)}\n"
                )

                file.write(
                    f"ASCII      : "
                    f"{bytes_to_ascii(data)}\n"
                )


        # ==========================================================
        # AUTHENTICATION INFORMATION
        # ==========================================================

        file.write("\n\n")

        file.write(
            "[AUTHENTICATION]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )

        file.write(
            "Authentication method    : MIFARE Classic Key A\n"
        )

        file.write(
            "Key attempted            : "
            f"{bytes_to_hex(DEFAULT_KEY)}\n"
        )

        file.write(
            "Note                     : "
            "Authentication information is recorded only as "
            "the attempted method/result. The scanner does not "
            "write to the card.\n"
        )

        file.write("\n")


        # ==========================================================
        # STATISTICS
        # ==========================================================

        file.write(
            "[SCAN STATISTICS]\n"
        )

        file.write(
            "-" * 78 + "\n"
        )

        file.write(
            f"Sectors authenticated   : "
            f"{sectors_authenticated}/16\n"
        )

        file.write(
            f"Authentication failures : "
            f"{authentication_failed}\n"
        )

        file.write(
            f"Blocks read successfully: "
            f"{blocks_read}/64\n"
        )

        file.write(
            f"Blocks failed           : "
            f"{blocks_failed}\n"
        )

        file.write(
            f"Total block records     : "
            f"{len(memory)}\n"
        )

        file.write("\n")


        # ==========================================================
        # END
        # ==========================================================

        file.write(
            "=" * 78 + "\n"
        )

        file.write(
            "                    END OF RFID SCAN\n"
        )

        file.write(
            "=" * 78 + "\n"
        )


    return filepath


# ======================================================================
# MAIN
# ======================================================================

def main():

    # --------------------------------------------------------------
    # Startup
    # --------------------------------------------------------------

    section(
        "RFID-RC522 EXTREME VERBOSE LOGGER"
    )

    print(
        "Raspberry Pi Zero 2 W"
    )

    print(
        "Mode: READ ONLY"
    )

    print(
        "Reader: MFRC522 / RC522"
    )

    print()

    print(
        "This program will continuously monitor the RC522."
    )

    print(
        "A separate TXT file will be created for every new card."
    )

    print()

    print(
        f"Scan directory:"
    )

    print(
        f"    {SCAN_DIRECTORY}"
    )


    create_scan_directory()


    # --------------------------------------------------------------
    # GPIO
    # --------------------------------------------------------------

    section(
        "GPIO / SPI INITIALISATION"
    )

    print(
        "Setting GPIO warnings to disabled..."
    )

    GPIO.setwarnings(False)

    print(
        "Setting GPIO numbering mode to BCM..."
    )

    GPIO.setmode(
        GPIO.BCM
    )

    print(
        "GPIO mode configured."
    )

    print()

    print(
        "Expected RC522 SPI configuration:"
    )

    print(
        "    MOSI = GPIO10 / physical pin 19"
    )

    print(
        "    MISO = GPIO9  / physical pin 21"
    )

    print(
        "    SCK  = GPIO11 / physical pin 23"
    )

    print(
        "    SDA  = GPIO8  / physical pin 24 / CE0"
    )

    print(
        "    RST  = GPIO25 / physical pin 22"
    )


    # --------------------------------------------------------------
    # RC522
    # --------------------------------------------------------------

    section(
        "RC522 INITIALISATION"
    )

    print(
        "Creating MFRC522 reader object..."
    )


    try:

        reader = MFRC522()

    except Exception as error:

        print()
        print(
            "!!! RC522 INITIALISATION FAILED !!!"
        )

        print(
            f"Error: {error}"
        )

        GPIO.cleanup()

        return


    print(
        "MFRC522 object created successfully."
    )

    print(
        "The Python library has initialised the RC522."
    )


    # --------------------------------------------------------------
    # Scan counter
    # --------------------------------------------------------------

    scan_id = get_next_scan_id()


    print()
    print(
        f"Next scan ID: {scan_id:03d}"
    )


    # --------------------------------------------------------------
    # Active mode
    # --------------------------------------------------------------

    section(
        "SCANNER ACTIVE"
    )

    print(
        "Waiting for an ISO14443A-compatible card/tag..."
    )

    print(
        "Place the card directly on the RC522 antenna."
    )

    print(
        "Do not place multiple cards on the antenna simultaneously."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()


    last_uid = None


    try:

        while True:

            # ======================================================
            # CARD REQUEST
            # ======================================================

            try:

                status, request_type = (
                    reader.MFRC522_Request(
                        reader.PICC_REQIDL
                    )
                )

            except Exception as error:

                print(
                    f"[REQUEST ERROR] {error}"
                )

                time.sleep(
                    1
                )

                continue


            if status != reader.MI_OK:

                time.sleep(
                    POLL_DELAY
                )

                continue


            # ======================================================
            # ANTICOLLISION / UID
            # ======================================================

            try:

                anticollision_status, uid = (
                    reader.MFRC522_Anticoll()
                )

            except Exception as error:

                print(
                    f"[ANTICOLLISION ERROR] {error}"
                )

                time.sleep(
                    POLL_DELAY
                )

                continue


            if anticollision_status != reader.MI_OK:

                print(
                    f"[ANTICOLLISION FAILED] "
                    f"Status: {anticollision_status}"
                )

                time.sleep(
                    POLL_DELAY
                )

                continue


            uid_values = normalise_bytes(
                uid
            )


            if not uid_values:

                print(
                    "[WARNING] Anticollision returned an empty UID."
                )

                time.sleep(
                    POLL_DELAY
                )

                continue


            uid_string = bytes_to_colon_hex(
                uid_values
            )


            # ======================================================
            # DUPLICATE DETECTION
            # ======================================================

            if uid_string == last_uid:

                time.sleep(
                    POLL_DELAY
                )

                continue


            # ======================================================
            # NEW CARD
            # ======================================================

            last_uid = uid_string

            timestamp = datetime.now()


            section(
                "NEW CARD DETECTED"
            )

            print(
                f"Scan ID       : {scan_id:03d}"
            )

            print(
                f"Timestamp     : "
                f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
            )

            print()


            # ======================================================
            # REQUEST INFORMATION
            # ======================================================

            subsection(
                "CARD REQUEST / ATQA INFORMATION"
            )

            print(
                f"Request status : {status}"
            )

            print(
                f"Request value  : "
                f"{describe_request_type(request_type)}"
            )

            print(
                f"Raw request    : "
                f"{request_type}"
            )


            # ======================================================
            # UID INFORMATION
            # ======================================================

            subsection(
                "UID INFORMATION"
            )

            print(
                f"UID length     : "
                f"{len(uid_values)} bytes"
            )

            print(
                f"UID HEX        : "
                f"{bytes_to_hex(uid_values)}"
            )

            print(
                f"UID colon HEX  : "
                f"{bytes_to_colon_hex(uid_values)}"
            )

            print(
                f"UID decimal    : "
                f"{bytes_to_decimal(uid_values)}"
            )

            print(
                f"UID binary     : "
                f"{bytes_to_binary(uid_values)}"
            )

            print(
                f"UID ASCII      : "
                f"{bytes_to_ascii(uid_values)}"
            )


            # ======================================================
            # CARD SELECTION
            # ======================================================

            subsection(
                "CARD SELECTION"
            )

            print(
                "Sending SELECT command..."
            )

            print(
                "IMPORTANT:"
            )

            print(
                "MFRC522_SelectTag() returns the card's SAK value."
            )

            print(
                "It should NOT be compared directly against MI_OK."
            )


            try:

                sak = reader.MFRC522_SelectTag(
                    uid_values
                )

                print(
                    f"Raw SELECT result : {sak}"
                )

                print(
                    f"SAK               : "
                    f"{describe_sak(sak)}"
                )

                selection_result = (
                    "SELECT COMMAND COMPLETED"
                )


            except Exception as error:

                sak = None

                selection_result = (
                    f"SELECT EXCEPTION: {error}"
                )

                print(
                    f"SELECT ERROR: {error}"
                )


            # ======================================================
            # MIFARE CLASSIC MEMORY
            # ======================================================

            memory = []

            blocks_read = 0

            blocks_failed = 0

            authentication_failed = 0

            sectors_authenticated = 0


            section(
                "BEGIN MEMORY EXTRACTION"
            )

            print(
                "The program will now attempt MIFARE Classic "
                "authentication and memory reads."
            )

            print()

            print(
                "No data will be written to the card."
            )


            try:

                (
                    memory,
                    blocks_read,
                    blocks_failed,
                    authentication_failed,
                    sectors_authenticated
                ) = read_mifare_classic(
                    reader,
                    uid_values
                )

            except Exception as error:

                print()
                print(
                    "!!! MEMORY SCAN EXCEPTION !!!"
                )

                print(
                    f"Error: {error}"
                )

                print(
                    "The scan record will still be saved."
                )


            # ======================================================
            # SAVE
            # ======================================================

            section(
                "SAVING SCAN"
            )

            print(
                "Creating scan record..."
            )


            try:

                filepath = save_scan(

                    scan_id,

                    timestamp,

                    uid_values,

                    request_type,

                    sak,

                    selection_result,

                    memory,

                    blocks_read,

                    blocks_failed,

                    authentication_failed,

                    sectors_authenticated

                )


                print(
                    "Scan successfully saved."
                )

                print()

                print(
                    f"FILE:"
                )

                print(
                    f"    {filepath}"
                )


            except Exception as error:

                filepath = None

                print(
                    "!!! FILE SAVE ERROR !!!"
                )

                print(
                    f"Error: {error}"
                )


            # ======================================================
            # FINAL SCAN SUMMARY
            # ======================================================

            section(
                "SCAN COMPLETE"
            )

            print(
                f"Scan ID                  : "
                f"{scan_id:03d}"
            )

            print(
                f"UID                      : "
                f"{uid_string}"
            )

            print(
                f"UID length               : "
                f"{len(uid_values)} bytes"
            )

            print(
                f"Request / ATQA           : "
                f"{describe_request_type(request_type)}"
            )

            print(
                f"SAK                      : "
                f"{describe_sak(sak)}"
            )

            print(
                f"Sectors authenticated   : "
                f"{sectors_authenticated}/16"
            )

            print(
                f"Authentication failures : "
                f"{authentication_failed}"
            )

            print(
                f"Blocks read successfully: "
                f"{blocks_read}/64"
            )

            print(
                f"Blocks failed            : "
                f"{blocks_failed}"
            )

            print(
                f"Total block records      : "
                f"{len(memory)}"
            )

            if filepath:

                print(
                    f"Saved file               : "
                    f"{filepath}"
                )


            # ======================================================
            # CARD REMOVAL
            # ======================================================

            section(
                "WAITING FOR CARD REMOVAL"
            )

            print(
                f"Current card UID:"
            )

            print(
                f"    {uid_string}"
            )

            print()

            print(
                "Remove the card from the RC522."
            )


            while True:

                time.sleep(
                    CARD_REMOVAL_CHECK_DELAY
                )


                try:

                    removal_status, _ = (
                        reader.MFRC522_Request(
                            reader.PICC_REQIDL
                        )
                    )

                except Exception:

                    removal_status = -1


                if removal_status != reader.MI_OK:

                    break


            print()
            print(
                "Card removal detected."
            )

            print(
                "RC522 is ready for another card."
            )


            last_uid = None

            scan_id += 1


            print()

            separator("=")

            print(
                "WAITING FOR NEXT CARD..."
            )

            separator("=")


    except KeyboardInterrupt:

        print()
        print()
        separator("=")

        print(
            "STOP REQUESTED"
        )

        separator("=")

        print(
            "CTRL+C received."
        )


    finally:

        print()
        print(
            "Stopping MIFARE authentication..."
        )


        try:

            reader.MFRC522_StopCrypto1()

        except Exception:

            pass


        print(
            "Cleaning up GPIO..."
        )

        GPIO.cleanup()

        print(
            "GPIO cleanup complete."
        )

        print()
        print(
            "RFID scanner stopped."
        )

        print()


# ======================================================================
# ENTRY POINT
# ======================================================================

if __name__ == "__main__":

    main()