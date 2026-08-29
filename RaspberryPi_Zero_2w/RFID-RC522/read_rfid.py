#!/usr/bin/env python3

"""
============================================================
              RFID-RC522 CARD LOGGER
              Raspberry Pi Zero 2 W
============================================================

ONE CARD PLACEMENT = ONE SCAN

The reader continuously polls internally, but the program will
only perform one complete interrogation for a card placement.

The same card cannot be scanned again until it has been
physically removed from the reader.

RC522:

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
import io
import contextlib
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

# Normal polling speed while waiting for a card.
POLL_DELAY = 0.10

# How many consecutive "no card" responses are required
# before the program considers the card removed.
REMOVAL_CONFIRMATIONS = 5

# Small delay after completing a scan before beginning the
# removal detection phase.
POST_SCAN_DELAY = 0.25


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

    result = ""

    try:

        for value in data:

            value = int(value) & 0xFF

            if 32 <= value <= 126:
                result += chr(value)
            else:
                result += "."

    except TypeError:

        return str(data)

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
# LIBRARY OUTPUT SUPPRESSION
# ============================================================

def silent_call(function, *args, **kwargs):
    """
    Execute an mfrc522 library function while suppressing
    text that the library itself prints.

    The return value is unchanged.
    """

    buffer = io.StringIO()

    with contextlib.redirect_stdout(buffer):

        result = function(
            *args,
            **kwargs
        )

    return result


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

            continue

    return highest + 1


# ============================================================
# CARD POLLING
# ============================================================

def detect_card(reader):

    """
    Perform ONE silent card detection attempt.

    Returns:

        (True, tag_type, uid)

    or:

        (False, None, None)
    """

    try:

        status, tag_type = silent_call(
            reader.MFRC522_Request,
            reader.PICC_REQIDL
        )

    except Exception:

        return (
            False,
            None,
            None
        )


    if status != reader.MI_OK:

        return (
            False,
            None,
            None
        )


    try:

        status, uid = silent_call(
            reader.MFRC522_Anticoll
        )

    except Exception:

        return (
            False,
            None,
            None
        )


    if status != reader.MI_OK:

        return (
            False,
            None,
            None
        )


    if not uid:

        return (
            False,
            None,
            None
        )


    return (
        True,
        tag_type,
        uid
    )


# ============================================================
# WAIT FOR CARD REMOVAL
# ============================================================

def wait_until_removed(reader):

    """
    Remain in the CARD_PRESENT state until the reader has
    failed to detect a card several consecutive times.

    IMPORTANT:

    This function does NOT perform another scan.

    It only determines whether the card has disappeared.
    """

    consecutive_no_card = 0

    while True:

        time.sleep(
            POLL_DELAY
        )

        detected, _, _ = detect_card(
            reader
        )

        if detected:

            # Card is still physically present.
            consecutive_no_card = 0

            continue


        # No card detected this poll.
        consecutive_no_card += 1


        if (
            consecutive_no_card
            >= REMOVAL_CONFIRMATIONS
        ):

            return


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
        "Key A                : "
        + bytes_to_hex(DEFAULT_KEY)
    )

    print()


    for sector in range(16):

        first_block = sector * 4

        trailer_block = first_block + 3


        print(
            f"[SECTOR {sector:02d}]"
        )

        print(
            f"  Authentication block : "
            f"{trailer_block}"
        )

        print(
            "  Authenticating..."
        )


        try:

            auth_status = silent_call(
                reader.MFRC522_Auth,
                reader.PICC_AUTHENT1A,
                trailer_block,
                DEFAULT_KEY,
                uid
            )

        except Exception as error:

            auth_status = -1

            print(
                f"  Exception: {error}"
            )


        if auth_status != reader.MI_OK:

            authentication_failed += 1

            print(
                "  Authentication : FAILED"
            )

            print(
                f"  Status         : {auth_status}"
            )

            print(
                "  Blocks skipped : 0"
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


        print(
            "  Authentication : SUCCESS"
        )

        print(
            "  Reading blocks..."
        )

        print()


        for block in range(
            first_block,
            first_block + 4
        ):

            try:

                data = silent_call(
                    reader.MFRC522_Read,
                    block
                )

            except Exception as error:

                data = None

                print(
                    f"    Block {block:02d}: "
                    f"EXCEPTION - {error}"
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
                    f"    Block {block:02d}: "
                    f"READ SUCCESS"
                )

                print(
                    f"      HEX   : {hex_data}"
                )

                print(
                    f"      ASCII : {ascii_data}"
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
                    f"    Block {block:02d}: "
                    f"READ FAILED"
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


    try:

        silent_call(
            reader.MFRC522_StopCrypto1
        )

    except Exception:

        pass


    print("-" * 60)

    print(
        "MEMORY READ COMPLETE"
    )

    print(
        f"Blocks successfully read : "
        f"{blocks_read}"
    )

    print(
        f"Blocks failed            : "
        f"{blocks_failed}"
    )

    print(
        f"Authentication failures  : "
        f"{authentication_failed}"
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


    filename = (
        timestamp.strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
        + f"_{scan_id:03d}.txt"
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
        # SCAN INFORMATION
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
            "Interface            : "
            "SPI0 CE0\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # CARD IDENTIFICATION
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
        # RAW UID
        # ----------------------------------------------------

        file.write(
            "[RAW UID]\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

        file.write(
            f"Decimal : {list(uid)}\n"
        )

        file.write(
            f"HEX     : {bytes_to_hex(uid)}\n"
        )

        file.write(
            f"Colon   : {bytes_to_colon_hex(uid)}\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # MEMORY
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
                    f"{entry['block']:02d}\n"
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


        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        file.write(
            "\n[SCAN STATISTICS]\n"
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
        "              RFID-RC522 CARD LOGGER"
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
    # Version
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


    # --------------------------------------------------------
    # Ready
    # --------------------------------------------------------

    print("=" * 60)

    print(
        "RFID SCANNER ACTIVE"
    )

    print("=" * 60)

    print()

    print(
        "Place one RFID card/tag on the reader."
    )

    print()

    print(
        "IMPORTANT:"
    )

    print(
        "  One physical card placement = ONE scan."
    )

    print(
        "  The same card will NOT be scanned again"
    )

    print(
        "  until it has been physically removed."
    )

    print()

    print(
        "The reader polls silently while waiting."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()


    # ========================================================
    # STATE MACHINE
    # ========================================================

    # False = waiting for a new card
    # True  = a card has already been scanned and remains present

    card_locked = False


    try:

        while True:

            # =================================================
            # STATE 1:
            # WAITING FOR A NEW CARD
            # =================================================

            if not card_locked:

                detected, tag_type, uid = detect_card(
                    reader
                )


                if not detected:

                    time.sleep(
                        POLL_DELAY
                    )

                    continue


                # ---------------------------------------------
                # A CARD HAS BEEN DETECTED
                #
                # LOCK IMMEDIATELY.
                #
                # This happens BEFORE any memory operations.
                # ---------------------------------------------

                card_locked = True


                timestamp = datetime.now()

                uid_string = bytes_to_colon_hex(
                    uid
                )


                # ---------------------------------------------
                # CARD INFORMATION
                # ---------------------------------------------

                print()

                print("=" * 60)

                print(
                    "                    CARD DETECTED"
                )

                print("=" * 60)

                print()

                print(
                    f"Scan ID       : "
                    f"{scan_id:03d}"
                )

                print(
                    f"Timestamp     : "
                    f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
                )

                print(
                    f"UID           : "
                    f"{uid_string}"
                )

                print(
                    f"UID length    : "
                    f"{len(uid)} bytes"
                )

                print(
                    f"Tag type      : "
                    f"{describe_tag_type(tag_type)}"
                )

                print(
                    f"Raw UID       : "
                    f"{list(uid)}"
                )

                print()

                print(
                    "CARD LOCKED."
                )

                print(
                    "No second scan will be performed while "
                    "this card remains present."
                )


                # ---------------------------------------------
                # MEMORY
                # ---------------------------------------------

                (
                    memory,
                    blocks_read,
                    blocks_failed,
                    authentication_failed
                ) = read_mifare_classic(
                    reader,
                    uid
                )


                # ---------------------------------------------
                # SAVE
                # ---------------------------------------------

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
                    f"File saved:"
                )

                print(
                    f"  {filepath}"
                )

                print()

                print(
                    "SCAN COMPLETE"
                )

                print("-" * 60)

                print(
                    f"UID                    : "
                    f"{uid_string}"
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

                print("-" * 60)

                print()


                scan_id += 1


                # ---------------------------------------------
                # CARD REMOVAL
                # ---------------------------------------------

                print(
                    "Waiting for physical card removal..."
                )

                print(
                    "(No further scan will occur while "
                    "the card remains present.)"
                )


                time.sleep(
                    POST_SCAN_DELAY
                )


                wait_until_removed(
                    reader
                )


                # ---------------------------------------------
                # UNLOCK
                # ---------------------------------------------

                card_locked = False


                print()

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


            time.sleep(
                POLL_DELAY
            )


    except KeyboardInterrupt:

        print()

        print("=" * 60)

        print(
            "Stopping RFID scanner..."
        )

        print("=" * 60)


    finally:

        try:

            silent_call(
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