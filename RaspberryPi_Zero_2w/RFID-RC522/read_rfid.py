#!/usr/bin/env python3

"""
============================================================
             RFID-RC522 VERBOSE CARD LOGGER
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
    2. Detect card once.
    3. Display detailed information.
    4. Attempt supported memory reads.
    5. Save one complete scan report.
    6. Wait until the card is physically removed.
    7. Only then accept another scan.

Output:

    scans/
        YYYY-MM-DD_HH-MM-SS_ID.txt

IMPORTANT:

The RC522 does not magically expose every possible RFID/NFC
card's contents.

This program records everything that the RC522 and the installed
Python library are actually able to retrieve.

For MIFARE Classic-compatible cards, it attempts authenticated
memory reads using the factory/default Key A:

    FF FF FF FF FF FF

Authentication failures are recorded, not repeatedly printed by
the underlying library.
"""

import os
import sys
import time
import contextlib
import io

from datetime import datetime

import RPi.GPIO as GPIO
from mfrc522 import MFRC522


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIRECTORY = os.path.dirname(
    os.path.abspath(__file__)
)

SCAN_DIRECTORY = os.path.join(
    BASE_DIRECTORY,
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

# Number of consecutive failed card detections required
# before the program considers the card physically removed.
REMOVAL_CONFIRMATIONS = 4


# ============================================================
# FORMATTING
# ============================================================

def bytes_to_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data & 0xFF:02X}"

    try:
        return " ".join(
            f"{int(x) & 0xFF:02X}"
            for x in data
        )
    except TypeError:
        return str(data)


def bytes_to_colon_hex(data):

    if data is None:
        return ""

    if isinstance(data, int):
        return f"{data & 0xFF:02X}"

    try:
        return ":".join(
            f"{int(x) & 0xFF:02X}"
            for x in data
        )
    except TypeError:
        return str(data)


def bytes_to_ascii(data):

    if data is None:
        return ""

    if isinstance(data, int):
        data = [data]

    output = ""

    try:

        for value in data:

            value = int(value) & 0xFF

            if 32 <= value <= 126:
                output += chr(value)
            else:
                output += "."

    except TypeError:

        return str(data)

    return output


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
            f"0x{tag_type:02X} "
            f"({names.get(tag_type, 'Unknown')})"
        )

    return str(tag_type)


# ============================================================
# DIRECTORY
# ============================================================

def create_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


# ============================================================
# SCAN ID
# ============================================================

def get_next_scan_id():

    create_scan_directory()

    highest = 0

    for filename in os.listdir(
        SCAN_DIRECTORY
    ):

        if not filename.endswith(".txt"):
            continue

        try:

            number = int(
                filename
                .rsplit("_", 1)[-1]
                .replace(".txt", "")
            )

            highest = max(
                highest,
                number
            )

        except (
            ValueError,
            IndexError
        ):

            pass

    return highest + 1


# ============================================================
# SILENT LIBRARY CALL
# ============================================================

def silent_library_call(function, *args, **kwargs):
    """
    Calls a library function while suppressing text that the
    mfrc522 library writes directly to stdout.

    This prevents output such as:

        AUTH ERROR!!
        AUTH ERROR(status2reg & 0x08) != 0

    from appearing repeatedly.

    The actual return value is preserved.
    """

    captured_output = io.StringIO()

    with contextlib.redirect_stdout(captured_output):

        result = function(
            *args,
            **kwargs
        )

    return result


# ============================================================
# SAFE CARD REQUEST
# ============================================================

def request_card(reader):

    try:

        result = silent_library_call(
            reader.MFRC522_Request,
            reader.PICC_REQIDL
        )

        return result

    except Exception as error:

        return (
            None,
            None
        )


# ============================================================
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_for_card_removal(reader):

    confirmations = 0

    while confirmations < REMOVAL_CONFIRMATIONS:

        time.sleep(
            POLL_DELAY
        )

        status, _ = request_card(
            reader
        )

        if status == reader.MI_OK:

            confirmations = 0

        else:

            confirmations += 1

    return True


# ============================================================
# MIFARE CLASSIC MEMORY READER
# ============================================================

def read_mifare_classic(
    reader,
    uid
):

    memory = []

    blocks_read = 0

    blocks_failed = 0

    authentication_failed = 0


    print()
    print("=" * 60)
    print("              MIFARE CLASSIC MEMORY READ")
    print("=" * 60)

    print()
    print("Card type assumption : MIFARE Classic 1K")
    print("Sectors              : 16")
    print("Blocks per sector    : 4")
    print("Total blocks         : 64")
    print(
        "Authentication key   : "
        + bytes_to_hex(DEFAULT_KEY)
    )

    print()
    print(
        "The underlying library's repetitive authentication "
        "messages are suppressed."
    )

    print()


    # --------------------------------------------------------
    # 16 sectors
    # --------------------------------------------------------

    for sector in range(16):

        first_block = sector * 4

        trailer_block = first_block + 3


        print(
            f"[SECTOR {sector:02d}]"
        )

        print(
            f"  Authentication block : {trailer_block}"
        )

        print(
            "  Key A                 : "
            + bytes_to_hex(DEFAULT_KEY)
        )

        print(
            "  Authenticating..."
        )


        # ----------------------------------------------------
        # Authenticate
        # ----------------------------------------------------

        try:

            auth_status = silent_library_call(
                reader.MFRC522_Auth,
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


        # ----------------------------------------------------
        # Authentication failed
        # ----------------------------------------------------

        if auth_status != reader.MI_OK:

            authentication_failed += 1

            print(
                f"  Result                : FAILED"
            )

            print(
                f"  Library status        : {auth_status}"
            )

            print(
                "  Memory reads skipped for this sector."
            )

            print()

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
                    f"Key A authentication failed "
                    f"(status {auth_status})"

            })

            continue


        # ----------------------------------------------------
        # Authentication succeeded
        # ----------------------------------------------------

        print(
            "  Result                : SUCCESS"
        )

        print(
            "  Reading sector blocks..."
        )

        print()


        # ----------------------------------------------------
        # Read four blocks
        # ----------------------------------------------------

        for block in range(
            first_block,
            first_block + 4
        ):

            print(
                f"    Block {block:02d}: "
                f"reading..."
            )


            try:

                data = silent_library_call(
                    reader.MFRC522_Read,
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"      Exception: {error}"
                )


            if data is not None:

                blocks_read += 1

                hex_data = bytes_to_hex(
                    data
                )

                ascii_data = bytes_to_ascii(
                    data
                )


                print(
                    "      Result : READ SUCCESS"
                )

                print(
                    f"      HEX    : {hex_data}"
                )

                print(
                    f"      ASCII  : {ascii_data}"
                )


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

                print(
                    "      Result : READ FAILED"
                )

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


        print()


    # --------------------------------------------------------
    # Stop authentication
    # --------------------------------------------------------

    try:

        silent_library_call(
            reader.MFRC522_StopCrypto1
        )

    except Exception:

        pass


    print("-" * 60)

    print(
        "MIFARE Classic memory scan complete."
    )

    print(
        f"Blocks successfully read : {blocks_read}"
    )

    print(
        f"Blocks failed            : {blocks_failed}"
    )

    print(
        f"Authentication failures  : {authentication_failed}"
    )

    print("-" * 60)


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
            "=" * 60 + "\n"
        )

        file.write(
            "                 RFID SCAN RECORD\n"
        )

        file.write(
            "=" * 60 + "\n\n"
        )


        # ----------------------------------------------------
        # Scan information
        # ----------------------------------------------------

        file.write(
            "[SCAN INFORMATION]\n"
        )

        file.write(
            "-" * 60 + "\n"
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
            "Reader               : "
            "MFRC522 / RC522\n"
        )

        file.write(
            "Platform             : "
            "Raspberry Pi Zero 2 W\n"
        )

        file.write(
            "SPI Interface        : "
            "SPI0 CE0\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # Card identification
        # ----------------------------------------------------

        file.write(
            "[CARD IDENTIFICATION]\n"
        )

        file.write(
            "-" * 60 + "\n"
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
        # Raw UID
        # ----------------------------------------------------

        file.write(
            "[RAW UID]\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        file.write(
            str(list(uid))
            + "\n\n"
        )


        # ----------------------------------------------------
        # Memory
        # ----------------------------------------------------

        file.write(
            "[CARD MEMORY]\n"
        )

        file.write(
            "-" * 60 + "\n"
        )


        if not memory:

            file.write(
                "No memory data obtained.\n"
            )

        else:

            current_sector = None

            for entry in memory:

                sector = entry[
                    "sector"
                ]


                if sector != current_sector:

                    file.write("\n")

                    file.write(
                        f"SECTOR {sector:02d}\n"
                    )

                    file.write(
                        "^" * 60
                        + "\n"
                    )

                    current_sector = sector


                # Authentication failure

                if entry[
                    "block"
                ] is None:

                    file.write(
                        "Authentication : FAILED\n"
                    )

                    file.write(
                        f"Reason         : "
                        f"{entry['reason']}\n"
                    )

                    file.write("\n")

                    continue


                # Normal block

                file.write(
                    f"Block           : "
                    f"{entry['block']}\n"
                )

                file.write(
                    f"Status          : "
                    f"{entry['status']}\n"
                )


                if entry[
                    "data"
                ] is not None:

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
        # Statistics
        # ----------------------------------------------------

        file.write("\n")

        file.write(
            "[SCAN STATISTICS]\n"
        )

        file.write(
            "-" * 60 + "\n"
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
        # End
        # ----------------------------------------------------

        file.write(
            "=" * 60 + "\n"
        )

        file.write(
            "                  END OF RFID SCAN\n"
        )

        file.write(
            "=" * 60 + "\n"
        )


    return filepath


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print("=" * 60)

    print(
        "             RFID-RC522 VERBOSE CARD LOGGER"
    )

    print("=" * 60)

    print()


    create_scan_directory()


    print(
        "Scan directory:"
    )

    print(
        f"  {SCAN_DIRECTORY}"
    )

    print()


    # --------------------------------------------------------
    # GPIO
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # RC522
    # --------------------------------------------------------

    print(
        "Initialising RC522..."
    )

    reader = MFRC522()

    print(
        "RC522 initialised."
    )


    # --------------------------------------------------------
    # Version register
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


    # --------------------------------------------------------
    # Ready
    # --------------------------------------------------------

    scan_id = get_next_scan_id()


    print("=" * 60)

    print(
        "RFID scanner is now ACTIVE."
    )

    print()

    print(
        "Place ONE RFID card/tag on the reader."
    )

    print()

    print(
        "For every physical card placement:"
    )

    print(
        "  [1] Detect card"
    )

    print(
        "  [2] Read UID"
    )

    print(
        "  [3] Identify available information"
    )

    print(
        "  [4] Attempt supported memory access"
    )

    print(
        "  [5] Save one scan file"
    )

    print(
        "  [6] Wait for physical card removal"
    )

    print(
        "  [7] Accept the next card"
    )

    print()

    print(
        "The scanner remains silent while waiting."
    )

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 60)

    print()


    try:

        while True:

            # ------------------------------------------------
            # Wait for card
            # ------------------------------------------------

            status, tag_type = request_card(
                reader
            )


            if status != reader.MI_OK:

                time.sleep(
                    POLL_DELAY
                )

                continue


            # ------------------------------------------------
            # Anticollision / UID
            # ------------------------------------------------

            try:

                status, uid = silent_library_call(
                    reader.MFRC522_Anticoll
                )

            except Exception:

                time.sleep(
                    POLL_DELAY
                )

                continue


            if status != reader.MI_OK:

                time.sleep(
                    POLL_DELAY
                )

                continue


            if not uid:

                time.sleep(
                    POLL_DELAY
                )

                continue


            uid_string = bytes_to_colon_hex(
                uid
            )


            timestamp = datetime.now()


            # ------------------------------------------------
            # CARD DETECTED
            # ------------------------------------------------

            print()

            print("=" * 60)

            print(
                "                    CARD DETECTED"
            )

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
                f"Raw UID       : {list(uid)}"
            )

            print()

            print(
                "Beginning detailed card interrogation..."
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

            print(
                "                    SAVING SCAN"
            )

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
                "Scan file created successfully."
            )

            print()

            print(
                f"File     : {filepath}"
            )

            print(
                f"UID      : {uid_string}"
            )

            print(
                f"Blocks   : {blocks_read}"
            )

            print(
                f"Failed   : {blocks_failed}"
            )

            print(
                f"Auth fail: {authentication_failed}"
            )

            print()


            scan_id += 1


            # ------------------------------------------------
            # WAIT FOR REMOVAL
            # ------------------------------------------------

            print(
                "-" * 60
            )

            print(
                "WAITING FOR CARD REMOVAL"
            )

            print(
                "-" * 60
            )

            print()

            print(
                "The same card will NOT generate another scan "
                "until it is physically removed."
            )

            print(
                f"Removal confirmation requires "
                f"{REMOVAL_CONFIRMATIONS} consecutive "
                f"no-card readings."
            )

            print()


            wait_for_card_removal(
                reader
            )


            print(
                "Card removal confirmed."
            )

            print()

            print(
                "=" * 60
            )

            print(
                "READY FOR NEXT CARD"
            )

            print(
                "=" * 60
            )

            print()


    except KeyboardInterrupt:

        print()

        print("=" * 60)

        print(
            "Stopping RFID scanner..."
        )

        print("=" * 60)


    finally:

        try:

            silent_library_call(
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