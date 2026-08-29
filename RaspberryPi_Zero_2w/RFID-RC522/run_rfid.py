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


Every newly detected card gets its own file:

    scans/
        YYYY-MM-DD_HH-MM-SS_mmm_ID.txt


The program records all information that the RC522/library
successfully obtains from the card.

For MIFARE Classic cards, the program attempts to read the
available memory using the default factory key:

    FF FF FF FF FF FF

Protected sectors using another key are recorded as
authentication failures rather than being silently ignored.
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
    os.path.dirname(
        os.path.abspath(__file__)
    ),
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

POLL_DELAY = 0.10

CARD_REMOVED_DELAY = 0.50


# ============================================================
# FORMATTING FUNCTIONS
# ============================================================

def bytes_to_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    return " ".join(
        f"{int(x) & 0xFF:02X}"
        for x in data
    )


def bytes_to_colon_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    return ":".join(
        f"{int(x) & 0xFF:02X}"
        for x in data
    )


def bytes_to_ascii(data):

    if data is None:
        return ""

    if isinstance(data, int):
        data = [data]

    result = ""

    for value in data:

        value = int(value) & 0xFF

        if 32 <= value <= 126:
            result += chr(value)
        else:
            result += "."

    return result


def describe_tag_type(tag_type):

    if tag_type is None:
        return "Unknown"

    if isinstance(tag_type, int):

        names = {

            0x04:
                "PICC_REQIDL / ISO14443A",

            0x10:
                "PICC_REQALL / ISO14443A",

            0x44:
                "ISO14443A"

        }

        return (
            f"0x{tag_type:02X}"
            f" ({names.get(tag_type, 'Unknown')})"
        )

    return str(tag_type)


# ============================================================
# FILE MANAGEMENT
# ============================================================

def create_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


def get_next_scan_id():

    create_scan_directory()

    highest = 0

    for filename in os.listdir(
        SCAN_DIRECTORY
    ):

        if not filename.endswith(".txt"):
            continue

        try:

            #
            # Expected:
            #
            # 2026-08-29_12-30-15_001.txt
            #

            number_part = (
                filename
                .rsplit("_", 1)[1]
                .replace(".txt", "")
            )

            number = int(
                number_part
            )

            highest = max(
                highest,
                number
            )

        except (
            ValueError,
            IndexError
        ):

            continue

    return highest + 1


# ============================================================
# MIFARE CLASSIC READER
# ============================================================

def read_mifare_classic(
    reader,
    uid
):

    memory = []

    blocks_read = 0

    blocks_failed = 0

    authentication_failed = 0


    #
    # MIFARE Classic 1K:
    #
    # 16 sectors
    # 4 blocks per sector
    # 64 blocks total
    #

    for sector in range(16):

        first_block = sector * 4

        trailer_block = first_block + 3


        #
        # Authenticate using Key A.
        #

        auth_status = reader.MFRC522_Auth(
            reader.PICC_AUTHENT1A,
            trailer_block,
            DEFAULT_KEY,
            uid
        )


        if auth_status != reader.MI_OK:

            authentication_failed += 1

            memory.append({

                "sector":
                    sector,

                "block":
                    None,

                "status":
                    "AUTHENTICATION FAILED",

                "data":
                    None,

                "reason":
                    "Default Key A failed"

            })

            continue


        #
        # Sector authenticated.
        #

        for block in range(
            first_block,
            first_block + 4
        ):

            #
            # The library returns the block data.
            #

            data = reader.MFRC522_Read(
                block
            )


            #
            # Depending on library version,
            # MFRC522_Read() may return:
            #
            #     list
            #
            # or:
            #
            #     None
            #
            # We handle both.
            #

            if data is not None:

                blocks_read += 1

                memory.append({

                    "sector":
                        sector,

                    "block":
                        block,

                    "status":
                        "READ OK",

                    "data":
                        data,

                    "reason":
                        None

                })

            else:

                blocks_failed += 1

                memory.append({

                    "sector":
                        sector,

                    "block":
                        block,

                    "status":
                        "READ FAILED",

                    "data":
                        None,

                    "reason":
                        "MFRC522_Read returned no data"

                })


    #
    # Stop encryption/authentication.
    #

    reader.MFRC522_StopCrypto1()


    return (
        memory,
        blocks_read,
        blocks_failed,
        authentication_failed
    )


# ============================================================
# SAVE COMPLETE SCAN
# ============================================================

def save_scan(
    scan_id,
    timestamp,
    uid,
    tag_type,
    selection_status,
    memory,
    blocks_read,
    blocks_failed,
    authentication_failed
):

    create_scan_directory()


    timestamp_string = (
        timestamp.strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
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

        # ====================================================
        # HEADER
        # ====================================================

        file.write(
            "============================================================\n"
        )

        file.write(
            "                    RFID SCAN RECORD\n"
        )

        file.write(
            "============================================================\n"
        )

        file.write("\n")


        # ====================================================
        # SCAN INFORMATION
        # ====================================================

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
            f"Reader               : "
            f"MFRC522 / RC522\n"
        )

        file.write(
            f"SPI Interface        : "
            f"SPI0 CE0\n"
        )

        file.write("\n")


        # ====================================================
        # CARD IDENTIFICATION
        # ====================================================

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

        file.write(
            f"Card Selection       : "
            f"{selection_status}\n"
        )

        file.write("\n")


        # ====================================================
        # RAW UID
        # ====================================================

        file.write(
            "[RAW UID DATA]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            bytes_to_hex(uid)
        )

        file.write("\n\n")


        # ====================================================
        # MEMORY
        # ====================================================

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


                #
                # Authentication failure
                #

                if entry["block"] is None:

                    file.write(
                        "Authentication : FAILED\n"
                    )

                    file.write(
                        f"Reason         : "
                        f"{entry['reason']}\n"
                    )

                    continue


                #
                # Normal block
                #

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

                else:

                    file.write(
                        "HEX             : "
                        "READ FAILED\n"
                    )

                    file.write(
                        f"Reason          : "
                        f"{entry['reason']}\n"
                    )


                file.write("\n")


        # ====================================================
        # STATISTICS
        # ====================================================

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


        # ====================================================
        # END
        # ====================================================

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
# MAIN PROGRAM
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
        "Scan files will be stored in:"
    )

    print(
        f"  {SCAN_DIRECTORY}"
    )

    print()


    print(
        "Initialising RC522..."
    )


    #
    # GPIO configuration.
    #

    GPIO.setwarnings(False)

    GPIO.setmode(
        GPIO.BCM
    )


    #
    # Initialise RC522.
    #

    reader = MFRC522()


    print(
        "RC522 initialised."
    )

    print()


    #
    # Get next scan ID.
    #

    scan_id = get_next_scan_id()


    print(
        "RFID scanner is now active."
    )

    print(
        "Place an RFID card/tag on the reader."
    )

    print(
        "Each new card detection creates one scan file."
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
            # Request card.
            #

            status, tag_type = (
                reader.MFRC522_Request(
                    reader.PICC_REQIDL
                )
            )


            if status == reader.MI_OK:

                #
                # Anticollision.
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
                # Convert UID to string.
                #

                uid_string = (
                    bytes_to_colon_hex(uid)
                )


                #
                # Don't scan the same card repeatedly.
                #

                if uid_string == last_uid:

                    time.sleep(
                        POLL_DELAY
                    )

                    continue


                #
                # New card.
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
                    f"UID       : "
                    f"{uid_string}"
                )

                print(
                    f"Tag type  : "
                    f"{describe_tag_type(tag_type)}"
                )

                print()


                # ====================================================
                # SELECT CARD
                # ====================================================

                select_status = (
                    reader.MFRC522_SelectTag(
                        uid
                    )
                )


                if select_status == reader.MI_OK:

                    selection_result = (
                        "SUCCESS"
                    )

                    print(
                        "Card selected successfully."
                    )

                else:

                    selection_result = (
                        f"FAILED "
                        f"(status {select_status})"
                    )

                    print(
                        f"Card selection failed: "
                        f"{select_status}"
                    )


                # ====================================================
                # READ MEMORY
                # ====================================================

                memory = []

                blocks_read = 0

                blocks_failed = 0

                authentication_failed = 0


                #
                # Only attempt MIFARE memory access when
                # card selection succeeded.
                #

                if select_status == reader.MI_OK:

                    print(
                        "Attempting memory reads..."
                    )

                    print()


                    (
                        memory,
                        blocks_read,
                        blocks_failed,
                        authentication_failed
                    ) = read_mifare_classic(
                        reader,
                        uid
                    )


                else:

                    print(
                        "Skipping memory read because "
                        "card selection failed."
                    )


                # ====================================================
                # SAVE
                # ====================================================

                filepath = save_scan(

                    scan_id,

                    timestamp,

                    uid,

                    tag_type,

                    selection_result,

                    memory,

                    blocks_read,

                    blocks_failed,

                    authentication_failed

                )


                print()
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


                scan_id += 1


                # ====================================================
                # WAIT FOR CARD REMOVAL
                # ====================================================

                print(
                    "Waiting for card removal..."
                )


                while True:

                    time.sleep(
                        CARD_REMOVED_DELAY
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
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()