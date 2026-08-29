#!/usr/bin/env python3

"""
============================================================
 RFID-RC522 CARD LOGGER
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

Behaviour:

    1. Wait silently for a card.
    2. Detect the card once.
    3. Read UID / card identification.
    4. Attempt supported MIFARE Classic memory access.
    5. Suppress duplicate library diagnostic output.
    6. Save ONE complete scan to scans/.
    7. Wait until the card is physically removed.
    8. Only then allow another scan.

Each scan is stored as:

    scans/
        YYYY-MM-DD_HH-MM-SS_ID.txt
"""

import os
import sys
import time
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

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

POLL_DELAY = 0.10

# Number of consecutive "no card" results required before
# the card is considered physically removed.
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

            number_part = (
                filename
                .rsplit("_", 1)[1]
                .replace(".txt", "")
            )

            number = int(number_part)

            if number > highest:
                highest = number

        except (
            ValueError,
            IndexError
        ):
            continue

    return highest + 1


# ============================================================
# QUIET LIBRARY CALL
# ============================================================

def quiet_call(function, *args):

    """
    Executes a library function while suppressing anything
    that the MFRC522 Python library itself prints.

    This is specifically used because MFRC522_Auth() prints:

        AUTH ERROR!!
        AUTH ERROR(status2reg & 0x08) != 0

    directly to stdout.

    We suppress those library messages and allow the main
    program to report the result exactly once.
    """

    captured_output = StringIO()
    captured_error = StringIO()

    with redirect_stdout(captured_output):
        with redirect_stderr(captured_error):

            result = function(*args)

    return result


# ============================================================
# MIFARE CLASSIC MEMORY READER
# ============================================================

def read_mifare_classic(reader, uid):

    memory = []

    blocks_read = 0
    blocks_failed = 0
    authentication_failed = 0

    print()
    print("------------------------------------------------------------")
    print("              MIFARE CLASSIC MEMORY READ")
    print("------------------------------------------------------------")
    print()
    print("Card type assumption : MIFARE Classic 1K")
    print("Sectors              : 16")
    print("Blocks per sector    : 4")
    print("Total blocks         : 64")
    print(f"Key A                : {bytes_to_hex(DEFAULT_KEY)}")
    print()

    for sector in range(16):

        first_block = sector * 4
        trailer_block = first_block + 3

        print(
            f"[SECTOR {sector:02d}] "
            f"Authentication block: {trailer_block}"
        )

        print(
            f"  Authenticating with Key A..."
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # MFRC522_Auth() itself prints errors.
        #
        # quiet_call() prevents those messages from appearing
        # repeatedly in the terminal.
        # ----------------------------------------------------

        auth_status = quiet_call(
            reader.MFRC522_Auth,
            reader.PICC_AUTHENT1A,
            trailer_block,
            DEFAULT_KEY,
            uid
        )

        if auth_status != reader.MI_OK:

            authentication_failed += 1

            print(
                f"  Authentication : FAILED"
            )

            print(
                f"  Status         : {auth_status}"
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

            continue

        # ----------------------------------------------------
        # Authentication succeeded.
        # ----------------------------------------------------

        print(
            "  Authentication : SUCCESS"
        )

        print(
            "  Reading blocks..."
        )

        for block in range(
            first_block,
            first_block + 4
        ):

            try:

                data = quiet_call(
                    reader.MFRC522_Read,
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"  Block {block:02d}: "
                    f"READ ERROR - {error}"
                )

            if data is not None:

                blocks_read += 1

                print(
                    f"  Block {block:02d}: "
                    f"READ OK"
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
                    f"  Block {block:02d}: "
                    f"READ FAILED"
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

        # ----------------------------------------------------
        # Authentication is no longer required for this
        # sector once its blocks have been processed.
        # ----------------------------------------------------

        try:

            quiet_call(
                reader.MFRC522_StopCrypto1
            )

        except Exception:
            pass

    try:

        quiet_call(
            reader.MFRC522_StopCrypto1
        )

    except Exception:
        pass

    print()
    print("------------------------------------------------------------")
    print("              MEMORY READ COMPLETE")
    print("------------------------------------------------------------")
    print(
        f"Blocks successfully read : {blocks_read}"
    )
    print(
        f"Blocks failed            : {blocks_failed}"
    )
    print(
        f"Authentication failures  : {authentication_failed}"
    )
    print("------------------------------------------------------------")

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
            f"Decimal : {uid}\n"
        )

        file.write(
            f"HEX     : {bytes_to_hex(uid)}\n"
        )

        file.write(
            f"COLON   : {bytes_to_colon_hex(uid)}\n"
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

                    file.write("\n")

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
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_for_card_removal(reader):

    consecutive_no_card = 0

    while consecutive_no_card < REMOVAL_CONFIRMATIONS:

        time.sleep(POLL_DELAY)

        try:

            result = quiet_call(
                reader.MFRC522_Request,
                reader.PICC_REQIDL
            )

            status = result[0]

        except Exception:

            status = None

        if status == reader.MI_OK:

            # Card still present.
            consecutive_no_card = 0

        else:

            consecutive_no_card += 1

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("              RFID-RC522 CARD LOGGER")
    print("=" * 60)
    print()

    create_scan_directory()

    print("Scan directory:")
    print(f"  {SCAN_DIRECTORY}")
    print()

    print("Initialising GPIO...")

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)

    print("GPIO initialised.")
    print()

    print("Initialising RC522...")

    reader = MFRC522()

    print("RC522 initialised.")

    # --------------------------------------------------------
    # Read version register.
    # --------------------------------------------------------

    try:

        version = reader.MFRC522_ReadVersion()

        if isinstance(version, int):

            print(
                f"RC522 Version Register: "
                f"0x{version:02X}"
            )

        else:

            print(
                f"RC522 Version Register: "
                f"{version}"
            )

    except Exception:

        print(
            "RC522 Version Register: unavailable"
        )

    print()

    print("=" * 60)
    print("RFID SCANNER ACTIVE")
    print("=" * 60)
    print()
    print("Place one RFID card/tag on the reader.")
    print()
    print("One physical card placement = ONE scan.")
    print("The card must be physically removed before")
    print("another scan can occur.")
    print()
    print("The reader polls silently while waiting.")
    print("Press CTRL+C to stop.")
    print()

    scan_id = get_next_scan_id()

    try:

        while True:

            # ------------------------------------------------
            # SILENT POLLING
            #
            # Nothing is printed here.
            # ------------------------------------------------

            try:

                request_result = quiet_call(
                    reader.MFRC522_Request,
                    reader.PICC_REQIDL
                )

                status = request_result[0]
                tag_type = request_result[1]

            except Exception:

                time.sleep(POLL_DELAY)
                continue

            if status != reader.MI_OK:

                time.sleep(POLL_DELAY)
                continue

            # ------------------------------------------------
            # ANTICOLLISION
            # ------------------------------------------------

            try:

                anticoll_result = quiet_call(
                    reader.MFRC522_Anticoll
                )

                status = anticoll_result[0]
                uid = anticoll_result[1]

            except Exception:

                time.sleep(POLL_DELAY)
                continue

            if status != reader.MI_OK:

                time.sleep(POLL_DELAY)
                continue

            # ------------------------------------------------
            # CARD DETECTED
            # ------------------------------------------------

            timestamp = datetime.now()

            uid_string = bytes_to_colon_hex(uid)

            print()
            print("=" * 60)
            print("                    CARD DETECTED")
            print("=" * 60)
            print()

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
                "CARD LOCKED."
            )

            print(
                "No second scan will occur until "
                "the card is removed."
            )

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
            # SAVE
            # ------------------------------------------------

            print()
            print("=" * 60)
            print("                    SAVING SCAN")
            print("=" * 60)
            print()

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
                "File saved:"
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
                f"Blocks successfully    : "
                f"{blocks_read}"
            )

            print(
                f"Blocks failed          : "
                f"{blocks_failed}"
            )

            print(
                f"Authentication failures: "
                f"{authentication_failed}"
            )

            print(
                "------------------------------------------------------------"
            )

            print()

            scan_id += 1

            # ------------------------------------------------
            # WAIT FOR PHYSICAL REMOVAL
            #
            # Completely silent.
            # ------------------------------------------------

            print(
                "Waiting for physical card removal..."
            )

            wait_for_card_removal(reader)

            print(
                "CARD REMOVED."
            )

            print(
                "Card lock released."
            )

            print(
                "Ready for the next card."
            )

            print()

            # Small delay prevents an immediate re-detection
            # caused by the reader's RF field settling.
            time.sleep(0.25)

    except KeyboardInterrupt:

        print()
        print("=" * 60)
        print("Stopping RFID scanner...")
        print("=" * 60)

    finally:

        try:

            quiet_call(
                reader.MFRC522_StopCrypto1
            )

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