```python
#!/usr/bin/env python3

import spidev
import RPi.GPIO as GPIO
import time
import csv
import os
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

RST_PIN = 25

SPI_BUS = 0
SPI_DEVICE = 0       # CE0 / GPIO8

CSV_FILE = "rfid_log.csv"

# Prevents the same card from being logged continuously
# while it remains on the reader.
READ_COOLDOWN = 2.0


# ============================================================
# MFRC522 REGISTERS
# ============================================================

CommandReg = 0x01
CommIEnReg = 0x02
CommIrqReg = 0x04
ErrorReg = 0x06
FIFODataReg = 0x09
FIFOLevelReg = 0x0A
ControlReg = 0x0C
BitFramingReg = 0x0D

ModeReg = 0x11
TxControlReg = 0x14
TxASKReg = 0x15

TModeReg = 0x2A
TPrescalerReg = 0x2B
TReloadRegH = 0x2C
TReloadRegL = 0x2D


# ============================================================
# MFRC522 COMMANDS
# ============================================================

PCD_IDLE = 0x00
PCD_TRANSCEIVE = 0x0C
PCD_RESETPHASE = 0x0F

PICC_REQIDL = 0x26
PICC_ANTICOLL = 0x93


# ============================================================
# STATUS VALUES
# ============================================================

MI_OK = 0
MI_NOTAGERR = 1
MI_ERR = 2


# ============================================================
# MFRC522
# ============================================================

class MFRC522:

    def __init__(self):

        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)

        GPIO.setup(RST_PIN, GPIO.OUT)
        GPIO.output(RST_PIN, GPIO.HIGH)

        self.spi = spidev.SpiDev()

        self.spi.open(SPI_BUS, SPI_DEVICE)

        self.spi.max_speed_hz = 1000000
        self.spi.mode = 0
        self.spi.no_cs = False

        self.MFRC522_Init()


    # --------------------------------------------------------
    # REGISTER WRITE
    # --------------------------------------------------------

    def Write_MFRC522(self, addr, val):

        self.spi.xfer2([
            ((addr << 1) & 0x7E),
            val
        ])


    # --------------------------------------------------------
    # REGISTER READ
    # --------------------------------------------------------

    def Read_MFRC522(self, addr):

        response = self.spi.xfer2([
            ((addr << 1) & 0x7E) | 0x80,
            0x00
        ])

        return response[1]


    # --------------------------------------------------------
    # SET BIT MASK
    # --------------------------------------------------------

    def SetBitMask(self, reg, mask):

        tmp = self.Read_MFRC522(reg)

        self.Write_MFRC522(
            reg,
            tmp | mask
        )


    # --------------------------------------------------------
    # CLEAR BIT MASK
    # --------------------------------------------------------

    def ClearBitMask(self, reg, mask):

        tmp = self.Read_MFRC522(reg)

        self.Write_MFRC522(
            reg,
            tmp & (~mask)
        )


    # --------------------------------------------------------
    # ANTENNA ON
    # --------------------------------------------------------

    def AntennaOn(self):

        temp = self.Read_MFRC522(TxControlReg)

        if ~(temp & 0x03):

            self.SetBitMask(
                TxControlReg,
                0x03
            )


    # --------------------------------------------------------
    # RESET
    # --------------------------------------------------------

    def Reset(self):

        self.Write_MFRC522(
            CommandReg,
            PCD_RESETPHASE
        )


    # --------------------------------------------------------
    # INITIALIZE
    # --------------------------------------------------------

    def MFRC522_Init(self):

        GPIO.output(
            RST_PIN,
            GPIO.HIGH
        )

        self.Reset()

        self.Write_MFRC522(
            TModeReg,
            0x8D
        )

        self.Write_MFRC522(
            TPrescalerReg,
            0x3E
        )

        self.Write_MFRC522(
            TReloadRegL,
            30
        )

        self.Write_MFRC522(
            TReloadRegH,
            0
        )

        self.Write_MFRC522(
            TxASKReg,
            0x40
        )

        self.Write_MFRC522(
            ModeReg,
            0x3D
        )

        self.AntennaOn()


    # --------------------------------------------------------
    # COMMUNICATION
    # --------------------------------------------------------

    def MFRC522_ToCard(
        self,
        command,
        send_data
    ):

        back_data = []
        back_len = 0

        status = MI_ERR

        irq_en = 0x00
        wait_irq = 0x00

        if command == PCD_TRANSCEIVE:

            irq_en = 0x77
            wait_irq = 0x30

        self.Write_MFRC522(
            CommIEnReg,
            irq_en | 0x80
        )

        self.ClearBitMask(
            CommIrqReg,
            0x80
        )

        self.SetBitMask(
            FIFOLevelReg,
            0x80
        )

        self.Write_MFRC522(
            CommandReg,
            PCD_IDLE
        )

        for data in send_data:

            self.Write_MFRC522(
                FIFODataReg,
                data
            )

        self.Write_MFRC522(
            CommandReg,
            command
        )

        if command == PCD_TRANSCEIVE:

            self.SetBitMask(
                BitFramingReg,
                0x80
            )

        i = 2000

        while True:

            n = self.Read_MFRC522(
                CommIrqReg
            )

            i -= 1

            if not (
                i != 0
                and not (n & 0x01)
                and not (n & wait_irq)
            ):

                break

        self.ClearBitMask(
            BitFramingReg,
            0x80
        )

        if i != 0:

            if (
                self.Read_MFRC522(ErrorReg)
                & 0x1B
            ) == 0x00:

                status = MI_OK

                if (
                    n & irq_en & 0x01
                ):

                    status = MI_NOTAGERR

                elif command == PCD_TRANSCEIVE:

                    n = self.Read_MFRC522(
                        FIFOLevelReg
                    )

                    last_bits = (
                        self.Read_MFRC522(ControlReg)
                        & 0x07
                    )

                    if last_bits != 0:

                        back_len = (
                            (n - 1) * 8
                            + last_bits
                        )

                    else:

                        back_len = n * 8

                    if n == 0:

                        n = 1

                    elif n > 16:

                        n = 16

                    for _ in range(n):

                        back_data.append(
                            self.Read_MFRC522(
                                FIFODataReg
                            )
                        )

        return (
            status,
            back_data,
            back_len
        )


    # --------------------------------------------------------
    # REQUEST CARD
    # --------------------------------------------------------

    def Request(self, req_mode):

        self.Write_MFRC522(
            BitFramingReg,
            0x07
        )

        status, back_data, back_bits = (
            self.MFRC522_ToCard(
                PCD_TRANSCEIVE,
                [req_mode]
            )
        )

        if (
            status != MI_OK
            or back_bits != 0x10
        ):

            status = MI_ERR

        return status, back_data


    # --------------------------------------------------------
    # ANTICOLLISION
    # --------------------------------------------------------

    def Anticoll(self):

        ser_num = []

        self.Write_MFRC522(
            BitFramingReg,
            0x00
        )

        status, back_data, back_bits = (
            self.MFRC522_ToCard(
                PCD_TRANSCEIVE,
                [PICC_ANTICOLL, 0x20]
            )
        )

        if status == MI_OK:

            if len(back_data) == 5:

                checksum = 0

                for i in range(4):

                    checksum ^= back_data[i]

                if checksum != back_data[4]:

                    status = MI_ERR

                else:

                    ser_num = back_data

            else:

                status = MI_ERR

        return status, ser_num


    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    def close(self):

        self.spi.close()

        GPIO.cleanup()


# ============================================================
# CSV
# ============================================================

def initialise_csv():

    if not os.path.exists(CSV_FILE):

        with open(
            CSV_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "timestamp",
                "uid"
            ])


def log_card(uid):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        CSV_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            uid
        ])

        file.flush()

    print(
        f"[{timestamp}] RFID detected: {uid}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("======================================")
    print("       Raspberry Pi RFID Reader")
    print("======================================")
    print()

    print("Initialising RC522...")

    initialise_csv()

    reader = MFRC522()

    print("RC522 initialised.")
    print("Waiting for RFID cards...")
    print()

    print(
        f"Logging to: {CSV_FILE}"
    )

    print("Press CTRL+C to stop.")
    print()

    last_uid = None
    last_read_time = 0

    try:

        while True:

            status, _ = reader.Request(
                PICC_REQIDL
            )

            if status == MI_OK:

                status, uid = (
                    reader.Anticoll()
                )

                if status == MI_OK:

                    uid_string = ":".join(
                        f"{byte:02X}"
                        for byte in uid[:4]
                    )

                    current_time = time.time()

                    if (
                        uid_string != last_uid
                        or
                        current_time
                        - last_read_time
                        >= READ_COOLDOWN
                    ):

                        log_card(
                            uid_string
                        )

                        last_uid = uid_string

                        last_read_time = (
                            current_time
                        )

            time.sleep(0.1)

    except KeyboardInterrupt:

        print()
        print("Stopping RFID reader...")

    finally:

        reader.close()

        print(
            "GPIO and SPI cleaned up."
        )

        print(
            "Program terminated."
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
```
