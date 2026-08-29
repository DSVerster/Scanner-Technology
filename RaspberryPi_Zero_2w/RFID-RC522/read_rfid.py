#!/usr/bin/env python3

"""
============================================================
        RFID-RC522 CONTINUOUS CARD LOGGER
        Raspberry Pi Zero 2 W
============================================================

RC522 wiring:

    VCC  -> Pin 1   (3.3V)
    GND  -> Pin 6   (GND)
    RST  -> Pin 22  (GPIO25)
    MISO -> Pin 21  (GPIO9)
    MOSI -> Pin 19  (GPIO10)
    SCK  -> Pin 23  (GPIO11)
    SDA  -> Pin 24  (GPIO8 / CE0)
    IRQ  -> Not connected


IMPORTANT
---------

This program:

1. Continuously watches for RFID cards.
2. Detects a card once.
3. Reads its UID.
4. Attempts MIFARE Classic memory access.
5. Attempts all MIFARE Classic 1K blocks.
6. Records successful reads.
7. Records failed reads/authentication failures.
8. Saves ONE TXT file per physical card placement.
9. DOES NOT repeatedly scan a card while it remains
   on the reader.
10. Waits until the card is actually removed before
    allowing another scan.

Files are stored in:

    scans/

Example:

    scans/
        2026-08-29_03-15-42_001.txt
        2026-08-29_03-17-08_002.txt
        2026-08-29_03-20-51_003.txt


MIFARE Classic default Key A:

    FF FF FF FF FF FF

Only sectors accessible using this key will be read.

This program does NOT attempt to bypass protected sectors.
"""

import os
import time
from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import MFRC522


# ============================================================
# CONFIGURATION
# ============================================================

SCAN_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scans"
)

DEFAULT_KEY = [
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF
]

# Main polling interval
POLL_DELAY = 0.15

# Time between removal checks
REMOVAL_CHECK_DELAY = 0.25

# Number of consecutive "no card" results required
# before considering the card physically removed.
#
# This prevents brief communication glitches from causing
# the program to immediately scan the same card again.
REMOVAL_CONFIRMATIONS = 4


# ============================================================
# FORMATTING
# ============================================================

def bytes_to_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    try:
        return " ".join(
            f"{int(x) & 0xFF:02X}"
            for x in data
        )
    except TypeError:
        return f"{int(data) & 0xFF:02X}"


def bytes_to_colon_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    try:
        return ":".join(
            f"{int(x) & 0xFF:02X}"
            for x in data
        )
    except TypeError:
        return f"{int(data) & 0xFF:02X}"


def bytes_to_ascii(data):

    if data is None:
        return ""

    if isinstance(data, int):
        data = [data]

    output = ""

    for value in data:

        value = int(value) & 0xFF

        if 32 <= value <= 126:
            output += chr(value)
        else:
            output += "."

    return output


def describe_tag_type(tag_type):

    if tag_type is None:
        return "Unknown"

    if isinstance(tag_type, int):

        names = {
            0x04: "PICC_REQIDL / ISO14443A",
            0x10: "PICC_REQALL / ISO14443A",
            0x44: "ISO14443A"
        }

        return (
            f"0x{tag_type:02X} "
            f"({names.get(tag_type, 'Unknown')})"
        )

    return str(tag_type)


# ============================================================
# DIRECTORY / SCAN ID
# ============================================================

def create_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


def get_next_scan_id():

    create_scan_directory()

    highest = 0

    for filename in os.listdir(SCAN_DIRECTORY):

        if not filename.endswith(".txt"):
            continue

        try:

            number_part = (
                filename
                .rsplit("_", 1)[1]
                .replace(".txt", "")
            )

            number = int(number_part)

            if number > highest:
                highest = number

        except (ValueError, IndexError):

            continue

    return highest + 1


# ============================================================
# CARD DETECTION
# ============================================================

def detect_card(reader):

    """
    Perform one card detection attempt.

    Returns:

        (False, None, None)

    if no card was detected.

    OR:

        (True, tag_type, uid)

    if a card was detected.
    """

    try:

        status, tag_type = reader.MFRC522_Request(
            reader.PICC_REQIDL
        )

    except Exception:

        return False, None, None

    if status != reader.MI_OK:

        return False, None, None

    try:

        status, uid = reader.MFRC522_Anticoll()

    except Exception:

        return False, None, None

    if status != reader.MI_OK:

        return False, None, None

    if uid is None:

        return False, None, None

    return True, tag_type, uid


# ============================================================
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_for_card_removal(reader):

    """
    Wait until the currently scanned card has actually
    disappeared from the reader.

    Multiple consecutive failed detections are required.
    """

    print()
    print("Waiting for card removal...")
    print(
        f"Removal requires "
        f"{REMOVAL_CONFIRMATIONS} consecutive "
        f"no-card readings."
    )

    no_card_count = 0

    while True:

        time.sleep(
            REMOVAL_CHECK_DELAY
        )

        detected, _, _ = detect_card(reader)

        if detected:

            no_card_count = 0

            print(
                "  Card still present."
            )

        else:

            no_card_count += 1

            print(
                f"  No card detected "
                f"({no_card_count}/"
                f"{REMOVAL_CONFIRMATIONS})"
            )

            if no_card_count >= REMOVAL_CONFIRMATIONS:

                print(
                    "Card removal confirmed."
                )

                return


# ============================================================
# MIFARE CLASSIC MEMORY READER
# ============================================================

def read_mifare_classic(reader, uid):

    """
    Attempt to read a MIFARE Classic 1K card.

    MIFARE Classic 1K:

        16 sectors
        4 blocks per sector
        64 blocks total

    Block 0 is the manufacturer block.

    Block 3 of each sector is the sector trailer.

    The default factory Key A is used.
    """

    memory = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    print()
    print(
        "============================================================"
    )
    print(
        "MIFARE CLASSIC MEMORY SCAN"
    )
    print(
        "============================================================"
    )

    print(
        "Card type assumption : MIFARE Classic 1K"
    )

    print(
        "Sectors              : 16"
    )

    print(
        "Blocks per sector    : 4"
    )

    print(
        "Total blocks         : 64"
    )

    print(
        "Authentication key   : FF FF FF FF FF FF"
    )

    print()

    for sector in range(16):

        first_block = sector * 4
        trailer_block = first_block + 3

        print(
            f"[SECTOR {sector:02d}]"
        )

        print(
            f"  Authenticating using "
            f"Key A on block {trailer_block}..."
        )

        try:

            auth_status = reader.MFRC522_Auth(
                reader.PICC_AUTHENT1A,
                trailer_block,
                DEFAULT_KEY,
                uid
            )

        except Exception as error:

            print(
                f"  Authentication exception: {error}"
            )

            auth_status = -1

        if auth_status != reader.MI_OK:

            authentication_failed += 1

            print(
                f"  AUTHENTICATION FAILED "
                f"(status {auth_status})"
            )

            memory.append({
                "sector": sector,
                "block": None,
                "status": "AUTHENTICATION FAILED",
                "data": None,
                "reason": (
                    f"Key A authentication failed "
                    f"with status {auth_status}"
                )
            })

            print()

            continue

        print(
            "  Authentication SUCCESS"
        )

        print(
            "  Reading blocks..."
        )

        for block in range(
            first_block,
            first_block + 4
        ):

            print(
                f"    Block {block:02d}: ",
                end="",
                flush=True
            )

            try:

                data = reader.MFRC522_Read(
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"EXCEPTION - {error}"
                )

                memory.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ FAILED",
                    "data": None,
                    "reason": str(error)
                })

                blocks_failed += 1

                continue

            if data is not None:

                blocks_read += 1

                hex_data = bytes_to_hex(data)
                ascii_data = bytes_to_ascii(data)

                print(
                    "READ OK"
                )

                print(
                    f"      HEX   : {hex_data}"
                )

                print(
                    f"      ASCII : {ascii_data}"
                )

                memory.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ OK",
                    "data": data,
                    "reason": None
                })

            else:

                blocks_failed += 1

                print(
                    "READ FAILED"
                )

                memory.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ FAILED",
                    "data": None,
                    "reason": (
                        "MFRC522_Read returned no data"
                    )
                })

        print()

        try:
            reader.MFRC522_StopCrypto1()
        except Exception:
            pass

    try:
        reader.MFRC522_StopCrypto1()
    except Exception:
        pass

    print(
        "MIFARE memory scan finished."
    )

    print(
        f"  Blocks successfully read : {blocks_read}"
    )

    print(
        f"  Blocks failed            : {blocks_failed}"
    )

    print(
        f"  Authentication failures  : "
        f"{authentication_failed}"
    )

    return (
        memory,
        blocks_read,
        blocks_failed,
        authentication_failed
    )


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    scan_id,
    timestamp,
    uid,
    tag_type,
    memory,
    blocks_read,
    blocks_failed,
    authentication_failed
):

    create_scan_directory()

    timestamp_string = timestamp.strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    filename = (
        f"{timestamp_string}"
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

        file.write(
            "============================================================\n"
        )

        file.write(
            "                    RFID SCAN RECORD\n"
        )

        file.write(
            "============================================================\n\n"
        )

        # ----------------------------------------------------
        # SCAN INFORMATION
        # ----------------------------------------------------

        file.write(
            "[SCAN INFORMATION]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Scan ID              : "
            f"{scan_id:03d}\n"
        )

        file.write(
            f"Timestamp            : "
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        )

        file.write(
            "Reader               : MFRC522 / RC522\n"
        )

        file.write(
            "Interface            : SPI0 CE0\n"
        )

        file.write("\n")

        # ----------------------------------------------------
        # CARD IDENTIFICATION
        # ----------------------------------------------------

        file.write(
            "[CARD IDENTIFICATION]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"UID                  : "
            f"{bytes_to_colon_hex(uid)}\n"
        )

        file.write(
            f"UID HEX              : "
            f"{bytes_to_hex(uid)}\n"
        )

        file.write(
            f"UID Length           : "
            f"{len(uid)} bytes\n"
        )

        file.write(
            f"Tag Type             : "
            f"{describe_tag_type(tag_type)}\n"
        )

        file.write("\n")

        # ----------------------------------------------------
        # RAW UID
        # ----------------------------------------------------

        file.write(
            "[RAW UID DATA]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Decimal              : "
            f"{uid}\n"
        )

        file.write(
            f"HEX                  : "
            f"{bytes_to_hex(uid)}\n"
        )

        file.write(
            f"Colon HEX            : "
            f"{bytes_to_colon_hex(uid)}\n"
        )

        file.write(
            f"ASCII                : "
            f"{bytes_to_ascii(uid)}\n"
        )

        file.write("\n")

        # ----------------------------------------------------
        # MEMORY
        # ----------------------------------------------------

        file.write(
            "[CARD MEMORY]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        if not memory:

            file.write(
                "No memory data was obtained.\n"
            )

        else:

            current_sector = None

            for entry in memory:

                sector = entry["sector"]

                if sector != current_sector:

                    file.write("\n")

                    file.write(
                        f"SECTOR {sector}\n"
                    )

                    file.write(
                        "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
                    )

                    current_sector = sector

                if entry["block"] is None:

                    file.write(
                        "Authentication : FAILED\n"
                    )

                    file.write(
                        f"Reason         : "
                        f"{entry['reason']}\n"
                    )

                    continue

                file.write(
                    f"Block           : "
                    f"{entry['block']}\n"
                )

                file.write(
                    f"Status          : "
                    f"{entry['status']}\n"
                )

                if entry["data"] is not None:

                    file.write(
                        f"HEX             : "
                        f"{bytes_to_hex(entry['data'])}\n"
                    )

                    file.write(
                        f"ASCII           : "
                        f"{bytes_to_ascii(entry['data'])}\n"
                    )

                    file.write(
                        f"Decimal         : "
                        f"{entry['data']}\n"
                    )

                else:

                    file.write(
                        "HEX             : READ FAILED\n"
                    )

                    file.write(
                        f"Reason          : "
                        f"{entry['reason']}\n"
                    )

                file.write("\n")

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        file.write("\n")

        file.write(
            "[SCAN STATISTICS]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Blocks read successfully : "
            f"{blocks_read}\n"
        )

        file.write(
            f"Blocks failed            : "
            f"{blocks_failed}\n"
        )

        file.write(
            f"Authentication failures  : "
            f"{authentication_failed}\n"
        )

        file.write("\n")

        # ----------------------------------------------------
        # END
        # ----------------------------------------------------

        file.write(
            "============================================================\n"
        )

        file.write(
            "                    END OF RFID SCAN\n"
        )

        file.write(
            "============================================================\n"
        )

    return filepath


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print(
        "============================================================"
    )

    print(
        "                 RFID-RC522 CARD LOGGER"
    )

    print(
        "============================================================"
    )

    print()

    create_scan_directory()

    print(
        "Scan directory:"
    )

    print(
        f"  {SCAN_DIRECTORY}"
    )

    print()

    print(
        "Initialising GPIO..."
    )

    GPIO.setwarnings(False)

    GPIO.setmode(
        GPIO.BCM
    )

    print(
        "GPIO initialised."
    )

    print()

    print(
        "Initialising RC522..."
    )

    reader = MFRC522()

    print(
        "RC522 initialised."
    )

    print()

    # --------------------------------------------------------
    # CHECK VERSION REGISTER
    # --------------------------------------------------------

    try:

        version = reader.Read_MFRC522(
            reader.VersionReg
        )

        print(
            f"RC522 Version Register: "
            f"0x{version:02X}"
        )

    except Exception as error:

        print(
            f"Could not read RC522 version register: "
            f"{error}"
        )

    print()

    scan_id = get_next_scan_id()

    print(
        "============================================================"
    )

    print(
        "RFID scanner is now ACTIVE."
    )

    print(
        "Place ONE RFID card/tag on the reader."
    )

    print()

    print(
        "The program will:"
    )

    print(
        "  1. Detect the card."
    )

    print(
        "  2. Read its UID."
    )

    print(
        "  3. Attempt memory access."
    )

    print(
        "  4. Save one scan file."
    )

    print(
        "  5. Wait for physical card removal."
    )

    print(
        "  6. Only then accept another scan."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print(
        "============================================================"
    )

    print()

    try:

        while True:

            # ------------------------------------------------
            # WAIT FOR A CARD
            # ------------------------------------------------

            detected, tag_type, uid = detect_card(
                reader
            )

            if not detected:

                time.sleep(
                    POLL_DELAY
                )

                continue

            # ------------------------------------------------
            # CARD FOUND
            # ------------------------------------------------

            uid_string = bytes_to_colon_hex(uid)

            timestamp = datetime.now()

            print()
            print(
                "============================================================"
            )

            print(
                "                    CARD DETECTED"
            )

            print(
                "============================================================"
            )

            print(
                f"Scan ID       : {scan_id:03d}"
            )

            print(
                f"Timestamp     : "
                f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
            )

            print(
                f"UID           : {uid_string}"
            )

            print(
                f"UID length    : {len(uid)} bytes"
            )

            print(
                f"Tag type      : "
                f"{describe_tag_type(tag_type)}"
            )

            print(
                f"Raw UID       : {uid}"
            )

            print()

            print(
                "IMPORTANT:"
            )

            print(
                "This card will NOT be scanned again until "
                "it is removed."
            )

            print()

            # ------------------------------------------------
            # MEMORY READ
            # ------------------------------------------------

            (
                memory,
                blocks_read,
                blocks_failed,
                authentication_failed
            ) = read_mifare_classic(
                reader,
                uid
            )

            # ------------------------------------------------
            # SAVE FILE
            # ------------------------------------------------

            print()
            print(
                "============================================================"
            )

            print(
                "                    SAVING SCAN"
            )

            print(
                "============================================================"
            )

            filepath = save_scan(
                scan_id,
                timestamp,
                uid,
                tag_type,
                memory,
                blocks_read,
                blocks_failed,
                authentication_failed
            )

            print(
                f"File saved:"
            )

            print(
                f"  {filepath}"
            )

            print()

            print(
                "SCAN COMPLETE"
            )

            print(
                "------------------------------------------------------------"
            )

            print(
                f"UID                    : {uid_string}"
            )

            print(
                f"Blocks successfully read: {blocks_read}"
            )

            print(
                f"Blocks failed           : {blocks_failed}"
            )

            print(
                f"Authentication failures : "
                f"{authentication_failed}"
            )

            print(
                "------------------------------------------------------------"
            )

            # ------------------------------------------------
            # INCREMENT FILE NUMBER
            # ------------------------------------------------

            scan_id += 1

            # ------------------------------------------------
            # WAIT FOR REMOVAL
            # ------------------------------------------------

            wait_for_card_removal(
                reader
            )

            print()
            print(
                "============================================================"
            )

            print(
                "READY FOR NEXT CARD"
            )

            print(
                "============================================================"
            )

            print()

            # Small delay before restarting detection.
            time.sleep(0.5)

    except KeyboardInterrupt:

        print()
        print(
            "============================================================"
        )

        print(
            "Stopping RFID scanner..."
        )

        print(
            "============================================================"
        )

    finally:

        try:

            reader.MFRC522_StopCrypto1()

        except Exception:

            pass

        GPIO.cleanup()

        print(
            "GPIO cleaned up."
        )

        print(
            "RFID scanner stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()