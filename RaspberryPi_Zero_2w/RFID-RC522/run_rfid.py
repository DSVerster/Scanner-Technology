#!/usr/bin/env python3

"""
============================================================
 RFID-RC522 Full Scan Logger
 Raspberry Pi Zero 2 W
============================================================

Every RFID scan is saved as a separate TXT file:

    read-cards/
        2026-08-29_01-42-15_001.txt
        2026-08-29_01-45-32_002.txt
        2026-08-29_02-03-17_003.txt

The program continuously scans the RC522 and records:

    - Scan ID
    - Date and time
    - UID
    - UID length
    - ATQA
    - SAK
    - Card type
    - MIFARE Classic memory blocks
    - Raw hexadecimal memory data
    - ASCII representation
    - Authentication results
    - Read failures
    - Scan statistics

The program attempts to read all memory that the RC522 can
access. Protected memory cannot be read without the correct
authentication key.
"""

import os
import time
import spidev
import RPi.GPIO as GPIO
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

RST_PIN = 25

SPI_BUS = 0
SPI_DEVICE = 0       # CE0 / GPIO8

SPI_SPEED = 1_000_000

# All RFID scan files are stored here.
SCAN_DIRECTORY = "read-cards"

# Delay between reader checks.
SCAN_DELAY = 0.10

# Prevents the same card being scanned repeatedly while
# it remains sitting on the reader.
CARD_REMOVAL_DELAY = 1.0

# Default MIFARE Classic key.
DEFAULT_KEY = [
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF
]


# ============================================================
# MFRC522 REGISTERS
# ============================================================

CommandReg = 0x01
CommIEnReg = 0x02
DivIEnReg = 0x03
CommIrqReg = 0x04
DivIrqReg = 0x05
ErrorReg = 0x06
Status1Reg = 0x07
Status2Reg = 0x08
FIFODataReg = 0x09
FIFOLevelReg = 0x0A
ControlReg = 0x0C
BitFramingReg = 0x0D

ModeReg = 0x11
TxModeReg = 0x12
RxModeReg = 0x13
TxControlReg = 0x14
TxASKReg = 0x15

CRCResultRegH = 0x21
CRCResultRegL = 0x22

RFCfgReg = 0x26

TModeReg = 0x2A
TPrescalerReg = 0x2B
TReloadRegH = 0x2C
TReloadRegL = 0x2D

VersionReg = 0x37


# ============================================================
# MFRC522 COMMANDS
# ============================================================

PCD_IDLE = 0x00
PCD_AUTHENT = 0x0E
PCD_TRANSCEIVE = 0x0C
PCD_RESETPHASE = 0x0F
PCD_CALCCRC = 0x03


# ============================================================
# PICC COMMANDS
# ============================================================

PICC_REQIDL = 0x26
PICC_REQALL = 0x52
PICC_ANTICOLL = 0x93
PICC_SElECTTAG = 0x93

PICC_AUTHENT1A = 0x60
PICC_AUTHENT1B = 0x61

PICC_READ = 0x30
PICC_HALT = 0x50


# ============================================================
# STATUS
# ============================================================

MI_OK = 0
MI_NOTAGERR = 1
MI_ERR = 2


# ============================================================
# MFRC522 CLASS
# ============================================================

class MFRC522:

    def __init__(self):

        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)

        GPIO.setup(
            RST_PIN,
            GPIO.OUT
        )

        GPIO.output(
            RST_PIN,
            GPIO.HIGH
        )

        self.spi = spidev.SpiDev()

        self.spi.open(
            SPI_BUS,
            SPI_DEVICE
        )

        self.spi.max_speed_hz = SPI_SPEED
        self.spi.mode = 0

        self.reset()
        self.init_reader()


    # --------------------------------------------------------
    # Register access
    # --------------------------------------------------------

    def write_register(self, address, value):

        self.spi.xfer2([
            (address << 1) & 0x7E,
            value & 0xFF
        ])


    def read_register(self, address):

        response = self.spi.xfer2([
            ((address << 1) & 0x7E) | 0x80,
            0x00
        ])

        return response[1]


    # --------------------------------------------------------
    # Bit operations
    # --------------------------------------------------------

    def set_bit_mask(self, register, mask):

        current = self.read_register(register)

        self.write_register(
            register,
            current | mask
        )


    def clear_bit_mask(self, register, mask):

        current = self.read_register(register)

        self.write_register(
            register,
            current & (~mask & 0xFF)
        )


    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    def reset(self):

        GPIO.output(
            RST_PIN,
            GPIO.LOW
        )

        time.sleep(0.05)

        GPIO.output(
            RST_PIN,
            GPIO.HIGH
        )

        time.sleep(0.05)

        self.write_register(
            CommandReg,
            PCD_RESETPHASE
        )

        time.sleep(0.05)


    # --------------------------------------------------------
    # Initialise reader
    # --------------------------------------------------------

    def init_reader(self):

        self.write_register(
            TModeReg,
            0x8D
        )

        self.write_register(
            TPrescalerReg,
            0x3E
        )

        self.write_register(
            TReloadRegL,
            30
        )

        self.write_register(
            TReloadRegH,
            0
        )

        self.write_register(
            TxASKReg,
            0x40
        )

        self.write_register(
            ModeReg,
            0x3D
        )

        self.write_register(
            RFCfgReg,
            0x70
        )

        self.antenna_on()


    # --------------------------------------------------------
    # Antenna
    # --------------------------------------------------------

    def antenna_on(self):

        value = self.read_register(
            TxControlReg
        )

        if (value & 0x03) != 0x03:

            self.set_bit_mask(
                TxControlReg,
                0x03
            )


    # --------------------------------------------------------
    # Communication
    # --------------------------------------------------------

    def communicate(
        self,
        command,
        send_data
    ):

        back_data = []
        back_length = 0
        status = MI_ERR

        irq_enable = 0x00
        wait_irq = 0x00

        if command == PCD_AUTHENT:

            irq_enable = 0x12
            wait_irq = 0x10

        elif command == PCD_TRANSCEIVE:

            irq_enable = 0x77
            wait_irq = 0x30

        self.write_register(
            CommIEnReg,
            irq_enable | 0x80
        )

        self.clear_bit_mask(
            CommIrqReg,
            0x80
        )

        self.set_bit_mask(
            FIFOLevelReg,
            0x80
        )

        self.write_register(
            CommandReg,
            PCD_IDLE
        )

        for byte in send_data:

            self.write_register(
                FIFODataReg,
                byte
            )

        self.write_register(
            CommandReg,
            command
        )

        if command == PCD_TRANSCEIVE:

            self.set_bit_mask(
                BitFramingReg,
                0x80
            )

        timeout = 2000

        while True:

            irq = self.read_register(
                CommIrqReg
            )

            timeout -= 1

            if timeout == 0:
                break

            if irq & wait_irq:
                break

            if irq & 0x01:
                break

        self.clear_bit_mask(
            BitFramingReg,
            0x80
        )

        if timeout != 0:

            error = self.read_register(
                ErrorReg
            )

            if (error & 0x1B) == 0:

                status = MI_OK

                if irq & 0x01:

                    status = MI_NOTAGERR

                elif command == PCD_TRANSCEIVE:

                    fifo_level = self.read_register(
                        FIFOLevelReg
                    )

                    last_bits = (
                        self.read_register(
                            ControlReg
                        ) & 0x07
                    )

                    if last_bits:

                        back_length = (
                            (fifo_level - 1) * 8
                            + last_bits
                        )

                    else:

                        back_length = fifo_level * 8

                    if fifo_level == 0:
                        fifo_level = 1

                    if fifo_level > 16:
                        fifo_level = 16

                    for _ in range(fifo_level):

                        back_data.append(
                            self.read_register(
                                FIFODataReg
                            )
                        )

        return (
            status,
            back_data,
            back_length
        )


    # --------------------------------------------------------
    # Request card
    # --------------------------------------------------------

    def request(self, request_mode):

        self.write_register(
            BitFramingReg,
            0x07
        )

        status, data, bits = self.communicate(
            PCD_TRANSCEIVE,
            [request_mode]
        )

        if status != MI_OK or bits != 0x10:

            status = MI_ERR

        return (
            status,
            data
        )


    # --------------------------------------------------------
    # Anti-collision / UID
    # --------------------------------------------------------

    def anticoll(self):

        self.write_register(
            BitFramingReg,
            0x00
        )

        status, data, bits = self.communicate(
            PCD_TRANSCEIVE,
            [
                PICC_ANTICOLL,
                0x20
            ]
        )

        if status == MI_OK:

            if len(data) == 5:

                checksum = 0

                for i in range(4):

                    checksum ^= data[i]

                if checksum != data[4]:

                    return (
                        MI_ERR,
                        []
                    )

                return (
                    MI_OK,
                    data
                )

        return (
            MI_ERR,
            []
        )


    # --------------------------------------------------------
    # Select card
    # --------------------------------------------------------

    def select_tag(self, uid):

        buffer = [
            PICC_SElECTTAG,
            0x70
        ] + uid

        crc = self.calculate_crc(
            buffer
        )

        buffer += crc

        status, data, bits = self.communicate(
            PCD_TRANSCEIVE,
            buffer
        )

        if status == MI_OK and len(data) >= 3:

            return (
                MI_OK,
                data[0]
            )

        return (
            MI_ERR,
            None
        )


    # --------------------------------------------------------
    # CRC
    # --------------------------------------------------------

    def calculate_crc(self, data):

        self.clear_bit_mask(
            DivIrqReg,
            0x04
        )

        self.set_bit_mask(
            FIFOLevelReg,
            0x80
        )

        for byte in data:

            self.write_register(
                FIFODataReg,
                byte
            )

        self.write_register(
            CommandReg,
            PCD_CALCCRC
        )

        for _ in range(255):

            value = self.read_register(
                DivIrqReg
            )

            if value & 0x04:

                break

        crc_l = self.read_register(
            CRCResultRegL
        )

        crc_h = self.read_register(
            CRCResultRegH
        )

        return [
            crc_l,
            crc_h
        ]


    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    def authenticate(
        self,
        auth_mode,
        block_address,
        key,
        uid
    ):

        buffer = [
            auth_mode,
            block_address
        ] + key + uid[:4]

        status, _, _ = self.communicate(
            PCD_AUTHENT,
            buffer
        )

        status2 = self.read_register(
            Status2Reg
        )

        if (
            status == MI_OK
            and
            (status2 & 0x08)
        ):

            return MI_OK

        return MI_ERR


    # --------------------------------------------------------
    # Read block
    # --------------------------------------------------------

    def read_block(self, block_address):

        buffer = [
            PICC_READ,
            block_address
        ]

        crc = self.calculate_crc(
            buffer
        )

        buffer += crc

        status, data, bits = self.communicate(
            PCD_TRANSCEIVE,
            buffer
        )

        if (
            status == MI_OK
            and
            bits == 0x90
            and
            len(data) == 16
        ):

            return (
                MI_OK,
                data
            )

        return (
            MI_ERR,
            []
        )


    # --------------------------------------------------------
    # Stop authentication
    # --------------------------------------------------------

    def stop_crypto(self):

        self.clear_bit_mask(
            Status2Reg,
            0x08
        )


    # --------------------------------------------------------
    # Halt card
    # --------------------------------------------------------

    def halt_card(self):

        buffer = [
            PICC_HALT,
            0x00
        ]

        crc = self.calculate_crc(
            buffer
        )

        buffer += crc

        self.communicate(
            PCD_TRANSCEIVE,
            buffer
        )


    # --------------------------------------------------------
    # Determine card type
    # --------------------------------------------------------

    def determine_card_type(self, sak):

        if sak is None:
            return "Unknown"

        if sak == 0x08:
            return "MIFARE Classic 1K"

        if sak == 0x18:
            return "MIFARE Classic 4K"

        if sak == 0x09:
            return "MIFARE Mini"

        if sak == 0x00:
            return "MIFARE Ultralight / NTAG"

        if sak & 0x20:
            return "ISO/IEC 14443-4 compatible"

        return f"Unknown / SAK 0x{sak:02X}"


    # --------------------------------------------------------
    # Close
    # --------------------------------------------------------

    def close(self):

        self.spi.close()
        GPIO.cleanup()


# ============================================================
# DATA CONVERSION
# ============================================================

def bytes_to_hex(data):

    if not data:
        return ""

    return " ".join(
        f"{byte:02X}"
        for byte in data
    )


def bytes_to_colon_hex(data):

    if not data:
        return ""

    return ":".join(
        f"{byte:02X}"
        for byte in data
    )


def bytes_to_ascii(data):

    if not data:
        return ""

    result = ""

    for byte in data:

        if 32 <= byte <= 126:

            result += chr(byte)

        else:

            result += "."

    return result


# ============================================================
# SCAN DIRECTORY
# ============================================================

def create_scan_directory():

    os.makedirs(
        SCAN_DIRECTORY,
        exist_ok=True
    )


# ============================================================
# SCAN NUMBER
# ============================================================

def get_next_scan_number():

    create_scan_directory()

    highest = 0

    for filename in os.listdir(
        SCAN_DIRECTORY
    ):

        if (
            filename.endswith(".txt")
            and
            "_" in filename
        ):

            try:

                scan_id = int(
                    filename.rsplit(
                        "_",
                        1
                    )[1].replace(
                        ".txt",
                        ""
                    )
                )

                highest = max(
                    highest,
                    scan_id
                )

            except ValueError:

                pass

    return highest + 1


# ============================================================
# CREATE SCAN FILE
# ============================================================

def create_scan_file(
    scan_number,
    scan_data
):

    create_scan_directory()

    timestamp = datetime.now()

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
            "                    RFID SCAN RECORD\n"
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
            f"Timestamp     : {scan_data['timestamp']}\n"
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
            f"Card type     : {scan_data['card_type']}\n"
        )

        file.write(
            f"UID           : {scan_data['uid']}\n"
        )

        file.write(
            f"UID length    : {scan_data['uid_length']} bytes\n"
        )

        file.write(
            f"ATQA          : {scan_data['atqa']}\n"
        )

        file.write(
            f"SAK           : {scan_data['sak']}\n"
        )

        file.write("\n")


        # ----------------------------------------------------
        # Raw identification
        # ----------------------------------------------------

        file.write(
            "RAW IDENTIFICATION DATA\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"ATQA HEX      : {scan_data['atqa_raw']}\n"
        )

        file.write(
            f"SAK HEX       : {scan_data['sak_raw']}\n"
        )

        file.write(
            f"UID HEX       : {scan_data['uid_raw']}\n"
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

        if not scan_data["memory"]:

            file.write(
                "No readable memory blocks were obtained.\n"
            )

        else:

            for entry in scan_data["memory"]:

                file.write(
                    f"Sector {entry['sector']} - "
                    f"Block {entry['block']}\n"
                )

                file.write(
                    f"Authentication : "
                    f"{entry['authentication']}\n"
                )

                if entry["data"]:

                    file.write(
                        f"HEX             : "
                        f"{entry['hex']}\n"
                    )

                    file.write(
                        f"ASCII           : "
                        f"{entry['ascii']}\n"
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
        # Summary
        # ----------------------------------------------------

        file.write(
            "SCAN SUMMARY\n"
        )

        file.write(
            "------------------------------------------------------------\n"
        )

        file.write(
            f"Blocks attempted : "
            f"{scan_data['blocks_attempted']}\n"
        )

        file.write(
            f"Blocks read      : "
            f"{scan_data['blocks_read']}\n"
        )

        file.write(
            f"Blocks failed    : "
            f"{scan_data['blocks_failed']}\n"
        )

        file.write("\n")


        file.write(
            "============================================================\n"
        )

        file.write(
            "                      END OF SCAN\n"
        )

        file.write(
            "============================================================\n"
        )


    return filepath


# ============================================================
# SCAN CARD
# ============================================================

def scan_card(reader):

    scan_data = {

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3],

        "uid": "",
        "uid_raw": "",
        "uid_length": 0,

        "atqa": "",
        "atqa_raw": "",

        "sak": "",
        "sak_raw": "",

        "card_type": "Unknown",

        "memory": [],

        "blocks_attempted": 0,
        "blocks_read": 0,
        "blocks_failed": 0
    }


    # --------------------------------------------------------
    # Request card
    # --------------------------------------------------------

    status, atqa = reader.request(
        PICC_REQALL
    )

    if status != MI_OK:

        return None


    scan_data["atqa_raw"] = bytes_to_hex(
        atqa
    )

    scan_data["atqa"] = bytes_to_colon_hex(
        atqa
    )


    # --------------------------------------------------------
    # Read UID
    # --------------------------------------------------------

    status, uid = reader.anticoll()

    if status != MI_OK:

        return None


    scan_data["uid_raw"] = bytes_to_hex(
        uid
    )

    scan_data["uid"] = bytes_to_colon_hex(
        uid
    )

    scan_data["uid_length"] = len(uid)


    # --------------------------------------------------------
    # Select card / obtain SAK
    # --------------------------------------------------------

    status, sak = reader.select_tag(
        uid
    )

    if status == MI_OK:

        scan_data["sak"] = (
            f"0x{sak:02X}"
        )

        scan_data["sak_raw"] = (
            f"{sak:02X}"
        )

        scan_data["card_type"] = (
            reader.determine_card_type(
                sak
            )
        )

    else:

        scan_data["sak"] = "Unavailable"
        scan_data["sak_raw"] = "Unavailable"


    # --------------------------------------------------------
    # Read MIFARE Classic memory
    # --------------------------------------------------------

    if sak in (0x08, 0x18, 0x09):

        if sak == 0x08:

            total_blocks = 64

        elif sak == 0x18:

            total_blocks = 256

        else:

            total_blocks = 20


        authenticated_sector = None

        for block in range(total_blocks):

            # MIFARE Classic 1K / Mini:
            # 4 blocks per sector.
            #
            # MIFARE Classic 4K:
            # first 32 sectors have 4 blocks,
            # remaining sectors have 16 blocks.

            if sak == 0x18 and block >= 128:

                sector = (
                    32
                    + (block - 128) // 16
                )

                sector_start = (
                    128
                    + (sector - 32) * 16
                )

            else:

                sector = block // 4
                sector_start = sector * 4


            # Authenticate once at the start of each sector.

            if (
                authenticated_sector != sector
            ):

                auth_status = reader.authenticate(
                    PICC_AUTHENT1A,
                    block,
                    DEFAULT_KEY,
                    uid
                )

                authenticated_sector = sector

                if auth_status != MI_OK:

                    scan_data["blocks_attempted"] += 1
                    scan_data["blocks_failed"] += 1

                    scan_data["memory"].append({

                        "sector": sector,
                        "block": block,
                        "authentication": "FAILED",
                        "data": [],
                        "hex": "",
                        "ascii": "",
                        "reason":
                            "Authentication failed using "
                            "default key FF FF FF FF FF FF"
                    })

                    continue


            scan_data["blocks_attempted"] += 1

            status, data = reader.read_block(
                block
            )

            if status == MI_OK:

                scan_data["blocks_read"] += 1

                scan_data["memory"].append({

                    "sector": sector,
                    "block": block,
                    "authentication": "SUCCESS",
                    "data": data,
                    "hex": bytes_to_hex(data),
                    "ascii": bytes_to_ascii(data),
                    "reason": ""
                })

            else:

                scan_data["blocks_failed"] += 1

                scan_data["memory"].append({

                    "sector": sector,
                    "block": block,
                    "authentication": "SUCCESS",
                    "data": [],
                    "hex": "",
                    "ascii": "",
                    "reason":
                        "Block read failed"
                })


        reader.stop_crypto()


    # --------------------------------------------------------
    # Halt card
    # --------------------------------------------------------

    reader.halt_card()

    return scan_data


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print(
        "============================================================"
    )
    print(
        "              RFID-RC522 FULL SCAN LOGGER"
    )
    print(
        "============================================================"
    )
    print()

    create_scan_directory()

    next_scan = get_next_scan_number()

    print(
        "Scan files:"
    )

    print(
        f"  {os.path.abspath(SCAN_DIRECTORY)}"
    )

    print()

    print(
        "Initialising RC522..."
    )

    reader = None

    try:

        reader = MFRC522()

        version = reader.read_register(
            VersionReg
        )

        print(
            f"RC522 Version Register: "
            f"0x{version:02X}"
        )

        if version in (0x91, 0x92):

            print(
                "RC522 detected successfully."
            )

        else:

            print(
                "WARNING: Unexpected RC522 "
                "version register."
            )

        print()

        print(
            "RFID scanner is active."
        )

        print(
            "Place an RFID card/tag on the reader."
        )

        print(
            "Each scan will be saved as a separate "
            "file in read-cards/."
        )

        print()

        print(
            "Press CTRL+C to stop."
        )

        print()


        card_present = False


        while True:

            status, _ = reader.request(
                PICC_REQALL
            )


            if status == MI_OK:

                if not card_present:

                    scan_data = scan_card(
                        reader
                    )

                    if scan_data is not None:

                        filepath = (
                            create_scan_file(
                                next_scan,
                                scan_data
                            )
                        )


                        print()
                        print(
                            "------------------------------------------------------------"
                        )

                        print(
                            f"SCAN ID       : "
                            f"{next_scan:03d}"
                        )

                        print(
                            f"UID           : "
                            f"{scan_data['uid']}"
                        )

                        print(
                            f"Card type     : "
                            f"{scan_data['card_type']}"
                        )

                        print(
                            f"Blocks read   : "
                            f"{scan_data['blocks_read']}"
                        )

                        print(
                            f"Blocks failed : "
                            f"{scan_data['blocks_failed']}"
                        )

                        print(
                            f"Saved to      : "
                            f"{filepath}"
                        )

                        print(
                            "------------------------------------------------------------"
                        )

                        print()


                        next_scan += 1

                    card_present = True


            else:

                if card_present:

                    time.sleep(
                        CARD_REMOVAL_DELAY
                    )

                    status, _ = reader.request(
                        PICC_REQALL
                    )

                    if status != MI_OK:

                        card_present = False


            time.sleep(
                SCAN_DELAY
            )


    except KeyboardInterrupt:

        print()
        print(
            "Stopping RFID scanner..."
        )


    finally:

        if reader is not None:

            reader.close()

        print(
            "SPI and GPIO cleaned up."
        )

        print(
            "RFID scanner stopped."
        )

        print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()