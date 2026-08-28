# RFID-RC522 Scanner — Raspberry Pi Zero 2 W

## 1. Overview

This project implements a basic RFID scanner using an **MFRC522 / RC522 RFID reader module** connected to a **Raspberry Pi Zero 2 W**.

The RFID reader communicates with the Raspberry Pi using the **SPI interface**.

The scanner is designed to:

* Continuously monitor the RC522 for RFID cards/tags.
* Detect the UID of an RFID card/tag.
* Record each detected UID.
* Record the date and time of each detection.
* Store the recorded data in a CSV file.
* Continue operating until manually stopped.
* Prevent the same card from being logged continuously while it remains on the reader.

---

# 2. Technology Stack

## Hardware

| Component            | Specification         |
| -------------------- | --------------------- |
| Computer             | Raspberry Pi Zero 2 W |
| RFID reader          | MFRC522 / RC522       |
| Communication        | SPI                   |
| RFID frequency       | 13.56 MHz             |
| RFID technology      | ISO/IEC 14443A        |
| Operating system     | Raspberry Pi OS       |
| Programming language | Python 3              |
| Data storage         | CSV                   |
| Interface            | GPIO / SPI            |

## Software

The scanner uses:

* Python 3
* `spidev`
* `RPi.GPIO`
* Linux SPI interface
* A self-contained MFRC522 driver

No dedicated RFID Python package is required.

---

# 3. Hardware Wiring

The RC522 is connected to the Raspberry Pi Zero 2 W using **SPI0**.

| RC522 Pin | Raspberry Pi Physical Pin |    BCM GPIO | Purpose         |
| --------- | ------------------------: | ----------: | --------------- |
| VCC       |                     Pin 1 |           — | 3.3 V power     |
| RST       |                    Pin 22 |      GPIO25 | RC522 reset     |
| GND       |                     Pin 6 |           — | Ground          |
| IRQ       |             Not connected |           — | Not required    |
| MISO      |                    Pin 21 |       GPIO9 | SPI MISO        |
| MOSI      |                    Pin 19 |      GPIO10 | SPI MOSI        |
| SCK       |                    Pin 23 |      GPIO11 | SPI clock       |
| SDA / SS  |                    Pin 24 | GPIO8 / CE0 | SPI chip select |

### Wiring diagram

```text
RC522                         Raspberry Pi Zero 2 W

VCC  ----------------------> Pin 1
                              3.3V

RST  ----------------------> Pin 22
                              GPIO25

GND  ----------------------> Pin 6
                              GND

IRQ  ----------------------> Not connected

MISO ----------------------> Pin 21
                              GPIO9

MOSI ----------------------> Pin 19
                              GPIO10

SCK  ----------------------> Pin 23
                              GPIO11

SDA  ----------------------> Pin 24
                              GPIO8 / CE0
```

## Important

The RC522 must be powered from **3.3 V**.

Do **not** connect RC522 VCC to the Raspberry Pi's 5 V supply.

Also note that the RC522 pin labelled **SDA** is being used as **SPI chip select (SS/CS/CE0)** in this configuration. It is not being used as I²C SDA.

---

# 4. Raspberry Pi Configuration

## 4.1 Enable SPI

Run:

```bash
sudo raspi-config
```

Navigate to:

```text
Interface Options
    → SPI
        → Enable
```

Reboot:

```bash
sudo reboot
```

---

## 4.2 Verify SPI

After reboot:

```bash
ls /dev/spidev*
```

The expected output is:

```text
/dev/spidev0.0
/dev/spidev0.1
```

The RC522 is connected to **CE0**, so the program uses:

```text
/dev/spidev0.0
```

---

# 5. Python Dependencies

Install the required system packages:

```bash
sudo apt update
sudo apt install -y python3-spidev python3-rpi.gpio
```

Verify the Python modules:

```bash
python3 -c "import spidev, RPi.GPIO; print('SPI/GPIO OK')"
```

Expected result:

```text
SPI/GPIO OK
```

No additional RFID-specific Python package is required.

---

# 6. Project Structure

Recommended structure:

```text
Scanner-Technology/
│
├── README.md
│
└── RFID/
    ├── README.md
    └── rfid_reader.py
```

When the program is first run, it will also create:

```text
RFID/
├── README.md
├── rfid_reader.py
└── rfid_log.csv
```

---

# 7. RFID Reader Program

The program is located at:

```text
RFID/rfid_reader.py
```

Run it with:

```bash
python3 rfid_reader.py
```

The program continuously scans the RC522.

When an RFID card is detected, its UID is written to:

```text
rfid_log.csv
```

The CSV contains:

```csv
timestamp,uid
2026-08-29 01:30:15,04:A1:B2:C3
2026-08-29 01:31:02,93:7F:21:8A
```

---

# 8. Duplicate Detection

An RFID card can remain within the RC522's detection range for an extended period.

Without duplicate handling, the scanner could record the same UID repeatedly:

```text
04:A1:B2:C3
04:A1:B2:C3
04:A1:B2:C3
04:A1:B2:C3
```

The program therefore uses a **2-second cooldown** for the same UID.

The value can be changed in the Python program:

```python
READ_COOLDOWN = 2.0
```

For example:

```python
READ_COOLDOWN = 5.0
```

would require five seconds before the same UID can be recorded again.

---

# 9. Data Format

Each record contains:

| Field     | Description                                  |
| --------- | -------------------------------------------- |
| timestamp | Date and time at which the card was detected |
| uid       | RFID card/tag UID                            |

Example:

```csv
timestamp,uid
2026-08-29 01:30:15,04:A1:B2:C3
2026-08-29 01:32:47,7B:19:32:04
```

The timestamp is generated using the Raspberry Pi's local system time.

---

# 10. Starting the Scanner

Navigate to the RFID directory:

```bash
cd ~/Scanner-Technology/RFID
```

Run:

```bash
python3 rfid_reader.py
```

Expected startup output:

```text
======================================
       Raspberry Pi RFID Reader
======================================

Initialising RC522...
RC522 initialised.
Waiting for RFID cards...

Logging to: rfid_log.csv
Press CTRL+C to stop.
```

When a card is detected:

```text
[2026-08-29 01:30:15] RFID detected: 04:A1:B2:C3
```

---

# 11. Stopping the Scanner

Press:

```text
CTRL+C
```

The program will stop the RFID reader and clean up the GPIO/SPI resources.

---

# 12. Troubleshooting

## `/dev/spidev0.0` does not exist

Check whether SPI is enabled:

```bash
sudo raspi-config
```

Enable:

```text
Interface Options → SPI → Enable
```

Then reboot.

---

## `ModuleNotFoundError: No module named 'spidev'`

Install:

```bash
sudo apt install python3-spidev
```

---

## `ModuleNotFoundError: No module named 'RPi'`

Install:

```bash
sudo apt install python3-rpi.gpio
```

---

## RC522 initializes but does not detect cards

Check the wiring carefully.

Particularly verify:

```text
VCC  → Pin 1
GND  → Pin 6
MISO → Pin 21
MOSI → Pin 19
SCK  → Pin 23
SDA  → Pin 24
RST  → Pin 22
```

Also verify that the RC522 is powered by **3.3 V**, not 5 V.

---

# 13. Current Limitations

This implementation is intended as a basic RFID scanning system.

It currently records:

* RFID UID
* Timestamp

It does not currently provide:

* User/card registration
* Database storage
* Authentication
* Access-control decisions
* Card names
* Cardholder information
* Network synchronization
* Web interface
* GUI
* RFID card writing
* Automatic startup as a Linux service

These features can be added later without changing the basic SPI wiring.

---

# 14. Future Development

Possible future additions include:

1. Card registration.
2. UID-to-user mapping.
3. SQLite database storage.
4. Access-control functionality.
5. Attendance logging.
6. Web/API integration.
7. Automatic startup using `systemd`.
8. Network synchronization.
9. Multiple RFID readers.
10. Reader status monitoring.
11. CSV export.
12. Centralized logging.

The current implementation intentionally keeps the hardware and software stack simple so that the RC522 communication can be verified before adding these features.
