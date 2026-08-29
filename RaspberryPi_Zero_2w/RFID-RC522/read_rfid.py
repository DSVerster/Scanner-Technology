#!/usr/bin/env python3

"""
============================================================
             RFID-RC522 CARD LOGGER
             Raspberry Pi Zero 2 W
============================================================

The program continuously monitors the RC522.

For each physical card placement:

    1. Detect card
    2. Read UID
    3. Attempt MIFARE Classic memory access
    4. Record every successful/failed operation
    5. Save ONE TXT file
    6. Wait silently for card removal
    7. Allow the next card

No repeated terminal output is produced while a card
remains on the reader.

RC522 wiring:

    VCC  -> Pin 1   (3.3V)
    GND  -> Pin 6   (GND)
    RST  -> Pin 22  (GPIO25)
    MISO -> Pin 21  (GPIO9)
    MOSI -> Pin 19  (GPIO10)
    SCK  -> Pin 23  (GPIO11)
    SDA  -> Pin 24  (GPIO8 / CE0)
    IRQ  -> Not connected
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

# How often the reader is polled.
POLL_DELAY = 0.10

# Delay between checks while waiting for removal.
REMOVAL_DELAY = 0.20

# Number of consecutive failed detections required to
# consider the card physically removed.
REMOVAL_CONFIRMATIONS = 3


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

    for filename in os.listdir(SCAN_DIRECTORY):

        if not filename.endswith(".txt"):
            continue

        try:

            number = int(
                filename
                .rsplit("_", 1)[1]
                .replace(".txt", "")
            )

            highest = max(
                highest,
                number
            )

        except (ValueError, IndexError):

            pass

    return highest + 1


# ============================================================
# CARD DETECTION
# ============================================================

def detect_card(reader):

    """
    Performs ONE silent card detection attempt.

    Returns:

        detected, tag_type, uid
    """

    try:

        status, tag_type = reader.MFRC522_Request(
            reader.PICC_REQIDL
        )

        if status != reader.MI_OK:
            return False, None, None

        status, uid = reader.MFRC522_Anticoll()

        if status != reader.MI_OK:
            return False, None, None

        if uid is None:
            return False, None, None

        return True, tag_type, uid

    except Exception:

        return False, None, None


# ============================================================
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_for_removal(reader):

    """
    Wait silently until the current card is gone.

    IMPORTANT:
    Nothing is printed during this loop.

    This prevents the terminal from being spammed while
    the card remains on the reader.
    """

    consecutive_failures = 0

    while True:

        time.sleep(
            REMOVAL_DELAY
        )

        detected, _, _ = detect_card(
            reader
        )

        if detected:

            # Card is still present.
            consecutive_failures = 0

        else:

            consecutive_failures += 1

            if consecutive_failures >= REMOVAL_CONFIRMATIONS:

                return


# ============================================================
# MIFARE CLASSIC MEMORY READER
# ============================================================

def read_mifare_classic(reader, uid):

    """
    Attempts to read all 64 blocks of a MIFARE Classic 1K.

    Authentication is attempted using:

        FF FF FF FF FF FF

    Every operation is reported to the terminal and stored
    in the scan file.
    """

    memory = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    print()
    print(
        "------------------------------------------------------------"
    )

    print(
        "MIFARE CLASSIC MEMORY READ"
    )

    print(
        "------------------------------------------------------------"
    )

    print(
        "Attempting 16 sectors / 64 blocks."
    )

    print(
        "Key A: FF FF FF FF FF FF"
    )

    print()

    for sector in range(16):

        first_block = sector * 4
        trailer_block = first_block + 3

        print(
            f"[Sector {sector:02d}] "
            f"Authenticating..."
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
                f"  Authentication exception: {error}"
            )

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
                    f"(status {auth_status})"
                )
            })

            print()

            continue

        print(
            "  Authentication successful."
        )

        for block in range(
            first_block,
            first_block + 4
        ):

            try:

                data = reader.MFRC522_Read(
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"  Block {block:02d}: "
                    f"READ EXCEPTION - {error}"
                )

                blocks_failed += 1

                memory.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ FAILED",
                    "data": None,
                    "reason": str(error)
                })

                continue

            if data is not None:

                blocks_read += 1

                print(
                    f"  Block {block:02d}: READ OK"
                )

                print(
                    f"      HEX   : "
                    f"{bytes_to_hex(data)}"
                )

                print(
                    f"      ASCII : "
                    f"{bytes_to_ascii(data)}"
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
                    f"  Block {block:02d}: READ FAILED"
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

        try:

            reader.MFRC522_StopCrypto1()

        except Exception:

            pass

        print()

    try:

        reader.MFRC522_StopCrypto1()

    except Exception:

        pass

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
        f"{timestamp_string}_"
        f"{scan_id:03d}.txt"
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
            f"Python/Decimal       : {uid}\n"
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
        # CARD MEMORY
        # ----------------------------------------------------

        file.write(
            "[CARD MEMORY]\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        if not memory:

            file.write(
                "No memory information obtained.\n"
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
        f"Scan directory: {SCAN_DIRECTORY}"
    )

    print()

    print(
        "Initialising RC522..."
    )

    GPIO.setwarnings(False)

    GPIO.setmode(
        GPIO.BCM
    )

    reader = MFRC522()

    print(
        "RC522 initialised."
    )

    # --------------------------------------------------------
    # RC522 VERSION
    # --------------------------------------------------------

    try:

        version = reader.Read_MFRC522(
            reader.VersionReg
        )

        print(
            f"RC522 Version Register: "
            f"0x{version:02X}"
        )

    except Exception:

        print(
            "RC522 Version Register: unavailable"
        )

    print()

    scan_id = get_next_scan_id()

    print(
        "RFID scanner ACTIVE."
    )

    print(
        "Place a card/tag on the reader."
    )

    print(
        "One file will be created per card placement."
    )

    print(
        "The scanner waits silently while a card remains "
        "on the reader."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()

    try:

        while True:

            # =================================================
            # WAIT FOR CARD
            # =================================================

            detected, tag_type, uid = detect_card(
                reader
            )

            if not detected:

                time.sleep(
                    POLL_DELAY
                )

                continue

            # =================================================
            # CARD DETECTED
            # =================================================

            timestamp = datetime.now()

            uid_string = bytes_to_colon_hex(
                uid
            )

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

            # =================================================
            # MEMORY
            # =================================================

            (
                memory,
                blocks_read,
                blocks_failed,
                authentication_failed
            ) = read_mifare_classic(
                reader,
                uid
            )

            # =================================================
            # SAVE
            # =================================================

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

            print()
            print(
                "------------------------------------------------------------"
            )

            print(
                "SCAN SAVED"
            )

            print(
                "------------------------------------------------------------"
            )

            print(
                f"File                  : {filepath}"
            )

            print(
                f"UID                   : {uid_string}"
            )

            print(
                f"Blocks successfully   : {blocks_read}"
            )

            print(
                f"Blocks failed         : {blocks_failed}"
            )

            print(
                f"Authentication failed : "
                f"{authentication_failed}"
            )

            print(
                "------------------------------------------------------------"
            )

            scan_id += 1

            # =================================================
            # WAIT FOR REMOVAL
            # =================================================

            print(
                "Waiting for card removal..."
            )

            wait_for_removal(
                reader
            )

            print(
                "Card removed. Ready for next scan."
            )

            print()

            time.sleep(
                0.3
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
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()