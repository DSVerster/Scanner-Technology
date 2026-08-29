#!/usr/bin/env python3

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
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF
]

POLL_DELAY = 0.10

# Number of consecutive "no card" readings required
# before a card is considered physically removed.
REMOVAL_CONFIRMATIONS = 4


# ============================================================
# FORMATTING
# ============================================================

def to_hex(data):
    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    return " ".join(
        f"{int(x) & 0xFF:02X}"
        for x in data
    )


def to_colon_hex(data):
    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data:02X}"

    return ":".join(
        f"{int(x) & 0xFF:02X}"
        for x in data
    )


def to_ascii(data):
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
            0x04: "ISO14443A / PICC_REQIDL",
            0x10: "ISO14443A / PICC_REQALL",
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
# MIFARE MEMORY READER
# ============================================================

def read_mifare_memory(reader, uid):

    results = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    #
    # MIFARE Classic 1K:
    #
    # 16 sectors
    # 4 blocks per sector
    # 64 blocks
    #

    for sector in range(16):

        first_block = sector * 4
        trailer_block = first_block + 3

        #
        # Authenticate sector.
        #

        try:
            auth_status = reader.MFRC522_Auth(
                reader.PICC_AUTHENT1A,
                trailer_block,
                DEFAULT_KEY,
                uid
            )

        except Exception as error:

            auth_status = -1

            results.append({
                "sector": sector,
                "block": None,
                "status": "AUTH ERROR",
                "data": None,
                "error": str(error)
            })

        if auth_status != reader.MI_OK:

            authentication_failed += 1

            if not any(
                r["sector"] == sector
                and r["status"] == "AUTH ERROR"
                for r in results
            ):
                results.append({
                    "sector": sector,
                    "block": None,
                    "status": "AUTHENTICATION FAILED",
                    "data": None,
                    "error": f"Status {auth_status}"
                })

            continue

        #
        # Authentication succeeded.
        #

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

                results.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ ERROR",
                    "data": None,
                    "error": str(error)
                })

                blocks_failed += 1

                continue

            if data is not None:

                blocks_read += 1

                results.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ OK",
                    "data": data,
                    "error": None
                })

            else:

                blocks_failed += 1

                results.append({
                    "sector": sector,
                    "block": block,
                    "status": "READ FAILED",
                    "data": None,
                    "error": "Reader returned no data"
                })

    try:
        reader.MFRC522_StopCrypto1()
    except Exception:
        pass

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

    timestamp_name = timestamp.strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    filename = (
        f"{timestamp_name}"
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

        file.write("[SCAN INFORMATION]\n")
        file.write("-" * 60 + "\n")

        file.write(
            f"Scan ID              : {scan_id:03d}\n"
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
        # CARD INFORMATION
        # ----------------------------------------------------

        file.write("[CARD INFORMATION]\n")
        file.write("-" * 60 + "\n")

        file.write(
            f"UID                  : "
            f"{to_colon_hex(uid)}\n"
        )

        file.write(
            f"UID HEX              : "
            f"{to_hex(uid)}\n"
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

        file.write("[RAW UID]\n")
        file.write("-" * 60 + "\n")

        file.write(
            f"Decimal              : {uid}\n"
        )

        file.write(
            f"HEX                  : {to_hex(uid)}\n"
        )

        file.write(
            f"Colon HEX            : {to_colon_hex(uid)}\n"
        )

        file.write("\n")

        # ----------------------------------------------------
        # MEMORY
        # ----------------------------------------------------

        file.write("[CARD MEMORY]\n")
        file.write("-" * 60 + "\n")

        if not memory:

            file.write(
                "No memory information was obtained.\n"
            )

        else:

            current_sector = None

            for entry in memory:

                sector = entry["sector"]

                if sector != current_sector:

                    file.write("\n")
                    file.write(
                        f"SECTOR {sector:02d}\n"
                    )
                    file.write(
                        "^" * 60 + "\n"
                    )

                    current_sector = sector

                if entry["block"] is None:

                    file.write(
                        f"Authentication status : "
                        f"{entry['status']}\n"
                    )

                    file.write(
                        f"Error                 : "
                        f"{entry.get('error', '')}\n"
                    )

                    file.write("\n")

                    continue

                file.write(
                    f"Block                 : "
                    f"{entry['block']:02d}\n"
                )

                file.write(
                    f"Status                : "
                    f"{entry['status']}\n"
                )

                if entry["data"] is not None:

                    file.write(
                        f"HEX                   : "
                        f"{to_hex(entry['data'])}\n"
                    )

                    file.write(
                        f"ASCII                 : "
                        f"{to_ascii(entry['data'])}\n"
                    )

                    file.write(
                        f"Decimal               : "
                        f"{entry['data']}\n"
                    )

                else:

                    file.write(
                        f"Error                 : "
                        f"{entry.get('error', '')}\n"
                    )

                file.write("\n")

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        file.write("\n")
        file.write("[SCAN STATISTICS]\n")
        file.write("-" * 60 + "\n")

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
# CARD DETECTION
# ============================================================

def detect_card(reader):

    try:

        status, tag_type = (
            reader.MFRC522_Request(
                reader.PICC_REQIDL
            )
        )

        if status != reader.MI_OK:
            return None

        status, uid = (
            reader.MFRC522_Anticoll()
        )

        if status != reader.MI_OK:
            return None

        return {
            "uid": uid,
            "tag_type": tag_type
        }

    except Exception:

        return None


# ============================================================
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_for_removal(reader):

    no_card_count = 0

    while no_card_count < REMOVAL_CONFIRMATIONS:

        time.sleep(
            POLL_DELAY
        )

        card = detect_card(reader)

        if card is None:

            no_card_count += 1

        else:

            no_card_count = 0

    try:
        reader.MFRC522_StopCrypto1()
    except Exception:
        pass


# ============================================================
# MAIN
# ============================================================

def main():

    create_scan_directory()

    print()
    print("=" * 60)
    print("                 RFID-RC522 CARD LOGGER")
    print("=" * 60)
    print()
    print(f"Scan directory: {SCAN_DIRECTORY}")
    print()
    print("Initialising RC522...")

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)

    reader = MFRC522()

    print("RC522 initialised.")

    #
    # Check version.
    #

    try:

        version = reader.MFRC522_Read(
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
    print("RFID scanner ACTIVE.")
    print("Place one card/tag on the reader.")
    print("One file will be created per card placement.")
    print("The terminal remains quiet while a card is present.")
    print()
    print("Press CTRL+C to stop.")
    print()

    scan_id = get_next_scan_id()

    try:

        while True:

            #
            # Wait silently for a card.
            #

            card = detect_card(reader)

            if card is None:

                time.sleep(
                    POLL_DELAY
                )

                continue

            uid = card["uid"]
            tag_type = card["tag_type"]

            uid_string = to_colon_hex(uid)

            timestamp = datetime.now()

            #
            # ONE compact terminal message.
            #

            print()
            print(
                f"[SCAN {scan_id:03d}] "
                f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | "
                f"UID={uid_string} | "
                f"TYPE={describe_tag_type(tag_type)}"
            )

            #
            # Read memory.
            #

            (
                memory,
                blocks_read,
                blocks_failed,
                authentication_failed
            ) = read_mifare_memory(
                reader,
                uid
            )

            #
            # Save complete scan.
            #

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

            #
            # ONE completion message.
            #

            print(
                f"[SCAN {scan_id:03d}] "
                f"Saved | "
                f"blocks={blocks_read} | "
                f"auth_failures={authentication_failed} | "
                f"file={os.path.basename(filepath)}"
            )

            scan_id += 1

            #
            # IMPORTANT:
            #
            # Do not scan again until the card has
            # actually been removed.
            #

            wait_for_removal(reader)

            print("[READY] Card removed. Waiting for next card.")

    except KeyboardInterrupt:

        print()
        print("Stopping RFID scanner...")

    finally:

        try:
            reader.MFRC522_StopCrypto1()
        except Exception:
            pass

        GPIO.cleanup()

        print("GPIO cleaned up.")
        print("RFID scanner stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()