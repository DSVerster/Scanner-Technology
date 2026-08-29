#!/usr/bin/env python3

"""
============================================================
 RFID-RC522 FULL CARD LOGGER
 Raspberry Pi Zero 2 W
============================================================

Hardware:

    RC522 SDA/SS -> GPIO8 / CE0
    RC522 SCK    -> GPIO11
    RC522 MOSI   -> GPIO10
    RC522 MISO   -> GPIO9
    RC522 RST    -> GPIO25
    RC522 3.3V   -> 3.3V
    RC522 GND    -> GND


Each detected RFID card is saved as its own file:

    scans/
        2026-08-29_02-35-10_001.txt
        2026-08-29_02-38-21_002.txt
        ...


The scanner attempts to collect:

    - Timestamp
    - Scan number
    - UID
    - UID bytes
    - Tag type / ATQA
    - MIFARE Classic memory
    - Sector number
    - Block number
    - Authentication status
    - Raw hexadecimal block data
    - ASCII representation
    - Read failures
    - Authentication failures


IMPORTANT:

The scanner cannot bypass unknown RFID authentication keys.

For MIFARE Classic cards it first attempts the standard:

    FF FF FF FF FF FF

key.

If a sector uses another key, the program records that the
sector could not be authenticated rather than pretending
that the memory is empty.
"""

import os
import time
from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import MFRC522


# ============================================================
# CONFIGURATION
# ============================================================

RST_PIN = 25

SCAN_DIRECTORY = "scans"

DEFAULT_KEY = [
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF
]

POLL_DELAY = 0.10

CARD_REMOVAL_DELAY = 0.75


# ============================================================
# HELPERS
# ============================================================

def hex_bytes(data):

    if not data:
        return ""

    return " ".join(
        f"{byte:02X}"
        for byte in data
    )


def colon_hex(data):

    if not data:
        return ""

    return ":".join(
        f"{byte:02X}"
        for byte in data
    )


def ascii_bytes(data):

    if not data:
        return ""

    result = ""

    for byte in data:

        if 32 <= byte <= 126:
            result += chr(byte)

        else:
            result += "."

    return result


def ensure_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


def next_scan_number():

    ensure_scan_directory()

    highest = 0

    for filename in os.listdir(
        SCAN_DIRECTORY
    ):

        if not filename.endswith(".txt"):
            continue

        try:

            number = int(
                filename.rsplit(
                    "_",
                    1
                )[1].replace(
                    ".txt",
                    ""
                )
            )

            if number > highest:
                highest = number

        except (ValueError, IndexError):

            continue

    return highest + 1


# ============================================================
# CARD TYPE
# ============================================================

def identify_card(tag_type):

    if tag_type is None:
        return "Unknown"

    value = hex_bytes(tag_type)

    return value


# ============================================================
# MIFARE CLASSIC MEMORY READING
# ============================================================

def read_mifare_classic(
    reader,
    uid,
    card_type
):

    results = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    #
    # The library's request/anticollision sequence has already
    # established the card. We now attempt standard MIFARE
    # Classic authentication and reads.
    #

    #
    # Start with a conservative 1K layout.
    #
    # 16 sectors × 4 blocks = 64 blocks.
    #

    total_blocks = 64

    #
    # Try each sector.
    #

    for sector in range(16):

        first_block = sector * 4

        trailer_block = first_block + 3

        #
        # Authenticate the sector using Key A.
        #

        status = reader.MFRC522_Auth(
            reader.PICC_AUTHENT1A,
            trailer_block,
            DEFAULT_KEY,
            uid
        )

        if status != reader.MI_OK:

            authentication_failed += 1

            results.append({
                "sector": sector,
                "block": None,
                "authentication": "FAILED",
                "data": None,
                "reason":
                    "Authentication failed using "
                    "FF FF FF FF FF FF"
            })

            continue


        #
        # Authentication succeeded.
        #
        # Read all four blocks in the sector.
        #

        for block in range(
            first_block,
            first_block + 4
        ):

            status, data = (
                reader.MFRC522_Read(
                    block
                )
            )

            if status == reader.MI_OK:

                blocks_read += 1

                results.append({
                    "sector": sector,
                    "block": block,
                    "authentication": "SUCCESS",
                    "data": data,
                    "reason": None
                })

            else:

                blocks_failed += 1

                results.append({
                    "sector": sector,
                    "block": block,
                    "authentication": "SUCCESS",
                    "data": None,
                    "reason":
                        "Block read failed"
                })


    #
    # Stop authentication.
    #

    reader.MFRC522_StopCrypto1()


    return (
        results,
        blocks_read,
        blocks_failed,
        authentication_failed
    )


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    scan_number,
    timestamp,
    uid,
    tag_type,
    memory,
    blocks_read,
    blocks_failed,
    authentication_failed
):

    ensure_scan_directory()

    filename = (
        timestamp.strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
        +
        f"_{scan_number:03d}.txt"
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
            "                 RFID SCAN RECORD\n"
        )

        file.write(
            "============================================================\n\n"
        )


        # ----------------------------------------------------
        # Scan information
        # ----------------------------------------------------

        file.write(
            "SCAN INFORMATION\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Scan ID       : {scan_number:03d}\n"
        )

        file.write(
            f"Timestamp     : "
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        )

        file.write(
            "Reader        : MFRC522 / RC522\n"
        )

        file.write(
            "Interface     : SPI0 / CE0\n"
        )

        file.write(
            f"RST GPIO      : GPIO{RST_PIN}\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # Card information
        # ----------------------------------------------------

        file.write(
            "CARD INFORMATION\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"UID           : {colon_hex(uid)}\n"
        )

        file.write(
            f"UID HEX       : {hex_bytes(uid)}\n"
        )

        file.write(
            f"UID length    : {len(uid)} bytes\n"
        )

        file.write(
            f"Tag type      : {identify_card(tag_type)}\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # Memory
        # ----------------------------------------------------

        file.write(
            "CARD MEMORY\n"
        )

        file.write(
            "------------------------------------------------------------\n\n"
        )


        if not memory:

            file.write(
                "No memory blocks were successfully processed.\n\n"
            )

        else:

            current_sector = None

            for entry in memory:

                sector = entry["sector"]

                if sector != current_sector:

                    file.write(
                        f"\n[SECTOR {sector}]\n"
                    )

                    current_sector = sector


                if entry["block"] is None:

                    file.write(
                        "Authentication : FAILED\n"
                    )

                    file.write(
                        f"Reason          : "
                        f"{entry['reason']}\n"
                    )

                    file.write("\n")

                    continue


                file.write(
                    f"Block           : "
                    f"{entry['block']}\n"
                )

                file.write(
                    f"Authentication  : "
                    f"{entry['authentication']}\n"
                )


                if entry["data"] is not None:

                    data = entry["data"]

                    file.write(
                        f"HEX             : "
                        f"{hex_bytes(data)}\n"
                    )

                    file.write(
                        f"ASCII           : "
                        f"{ascii_bytes(data)}\n"
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
        # Statistics
        # ----------------------------------------------------

        file.write(
            "SCAN STATISTICS\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Blocks successfully read : "
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


        file.write(
            "============================================================\n"
        )

        file.write(
            "                    END OF SCAN\n"
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


    ensure_scan_directory()

    scan_number = next_scan_number()


    print(
        f"Scan files will be stored in: "
        f"{os.path.abspath(SCAN_DIRECTORY)}"
    )

    print()


    #
    # Initialise GPIO.
    #

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)


    #
    # Create reader.
    #

    print(
        "Initialising RC522..."
    )

    reader = MFRC522()


    print(
        "RC522 initialised."
    )

    print()

    print(
        "RFID scanner is now active."
    )

    print(
        "Place an RFID card/tag on the reader."
    )

    print(
        "Each card detection creates one scan file."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()


    last_uid = None


    try:

        while True:

            #
            # Ask whether a card is present.
            #

            status, tag_type = (
                reader.MFRC522_Request(
                    reader.PICC_REQIDL
                )
            )


            if status == reader.MI_OK:

                #
                # Perform anticollision.
                #

                status, uid = (
                    reader.MFRC522_Anticoll()
                )


                if status != reader.MI_OK:

                    time.sleep(
                        POLL_DELAY
                    )

                    continue


                #
                # Convert UID into a stable string.
                #

                uid_string = colon_hex(
                    uid
                )


                #
                # Ignore the card while it remains
                # on the reader.
                #

                if uid_string == last_uid:

                    time.sleep(
                        POLL_DELAY
                    )

                    continue


                #
                # New card detected.
                #

                last_uid = uid_string

                timestamp = datetime.now()


                print()
                print(
                    "============================================================"
                )

                print(
                    "CARD DETECTED"
                )

                print(
                    "------------------------------------------------------------"
                )

                print(
                    f"UID       : {uid_string}"
                )

                print(
                    f"Tag type  : {identify_card(tag_type)}"
                )

                print()


                #
                # Select the card.
                #

                select_status, _ = (
                    reader.MFRC522_SelectTag(
                        uid
                    )
                )


                if select_status != reader.MI_OK:

                    print(
                        "WARNING: Card was detected but "
                        "could not be selected."
                    )

                    #
                    # Still save the identification data.
                    #

                    filepath = save_scan(
                        scan_number,
                        timestamp,
                        uid,
                        tag_type,
                        [],
                        0,
                        0,
                        0
                    )

                    print(
                        f"Scan saved: {filepath}"
                    )

                    scan_number += 1

                else:

                    print(
                        "Card selected successfully."
                    )

                    print(
                        "Attempting to read MIFARE Classic memory..."
                    )

                    print()


                    #
                    # Read memory.
                    #

                    (
                        memory,
                        blocks_read,
                        blocks_failed,
                        authentication_failed
                    ) = read_mifare_classic(
                        reader,
                        uid,
                        tag_type
                    )


                    #
                    # Save everything obtained.
                    #

                    filepath = save_scan(
                        scan_number,
                        timestamp,
                        uid,
                        tag_type,
                        memory,
                        blocks_read,
                        blocks_failed,
                        authentication_failed
                    )


                    print(
                        "SCAN COMPLETE"
                    )

                    print(
                        "------------------------------------------------------------"
                    )

                    print(
                        f"UID                    : "
                        f"{uid_string}"
                    )

                    print(
                        f"Blocks successfully read: "
                        f"{blocks_read}"
                    )

                    print(
                        f"Blocks failed           : "
                        f"{blocks_failed}"
                    )

                    print(
                        f"Authentication failures : "
                        f"{authentication_failed}"
                    )

                    print(
                        f"Saved to                : "
                        f"{filepath}"
                    )

                    print(
                        "------------------------------------------------------------"
                    )

                    print()


                    scan_number += 1


                #
                # Wait for card removal.
                #

                print(
                    "Waiting for card removal..."
                )


                while True:

                    time.sleep(
                        CARD_REMOVAL_DELAY
                    )

                    status, _ = (
                        reader.MFRC522_Request(
                            reader.PICC_REQIDL
                        )
                    )

                    if status != reader.MI_OK:

                        break


                last_uid = None

                print(
                    "Card removed."
                )

                print(
                    "Ready for next scan."
                )

                print()


            time.sleep(
                POLL_DELAY
            )


    except KeyboardInterrupt:

        print()
        print(
            "Stopping RFID scanner..."
        )


    finally:

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