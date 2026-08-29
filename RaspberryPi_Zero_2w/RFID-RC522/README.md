# RFID-RC522 Scanner

A continuously running RFID scanning system using an **MFRC522 / RC522 RFID reader** connected to a **Raspberry Pi Zero 2 W** through SPI.

The scanner detects RFID cards/tags, retrieves the information accessible through the RC522, and stores **each individual scan as a separate timestamped text file**.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Technology Stack](#technology-stack)
* [Hardware Requirements](#hardware-requirements)
* [Wiring](#wiring)
* [Raspberry Pi Setup](#raspberry-pi-setup)
* [Software Installation](#software-installation)
* [Project Structure](#project-structure)
* [Running the Scanner](#running-the-scanner)
* [Scan File Storage](#scan-file-storage)
* [Information Captured](#information-captured)
* [Example Scan File](#example-scan-file)
* [Duplicate Scan Prevention](#duplicate-scan-prevention)
* [Troubleshooting](#troubleshooting)
* [Future Improvements](#future-improvements)

---

# Overview

The system uses an **MFRC522 RFID reader** to continuously monitor for RFID cards and tags.

When a card is detected, the program attempts to retrieve as much information as the RC522 and the card's protocol allow.

For compatible MIFARE Classic cards, this includes reading the card's memory blocks after authentication.

Each completed scan is stored independently.

For example:

```text
read-cards/
├── 2026-08-29_01-42-15_001.txt
├── 2026-08-29_01-45-32_002.txt
└── 2026-08-29_02-03-17_003.txt
```

This makes every RFID read an independent record rather than placing all scans into one CSV file.

---

# Features

* Continuous RFID scanning
* MFRC522 / RC522 support
* Raspberry Pi Zero 2 W support
* SPI communication
* RFID UID detection
* ATQA capture
* SAK capture
* Card-type identification
* MIFARE Classic memory reading
* MIFARE Classic sector authentication
* Raw hexadecimal memory capture
* ASCII representation of memory
* Authentication/read failure reporting
* Timestamp for every scan
* Unique scan ID
* One file per RFID scan
* Automatic creation of the scan directory
* Automatic continuation of scan numbering after reboot
* No database required
* Local file storage
* Runs without an internet connection

---

# Technology Stack

| Category             | Technology              |
| -------------------- | ----------------------- |
| Computer             | Raspberry Pi Zero 2 W   |
| RFID reader          | MFRC522 / RC522         |
| RFID frequency       | 13.56 MHz               |
| Reader interface     | SPI                     |
| SPI bus              | SPI0                    |
| Chip select          | CE0 / GPIO8             |
| Operating system     | Raspberry Pi OS         |
| Programming language | Python 3                |
| SPI Python library   | `spidev`                |
| GPIO Python library  | `RPi.GPIO`              |
| Scan storage         | Plain-text `.txt` files |
| Storage directory    | `read-cards/`           |

---

# Hardware Requirements

## Required

* Raspberry Pi Zero 2 W
* MFRC522 / RC522 RFID reader
* RFID card/tag
* Female-to-female jumper wires
* MicroSD card
* Raspberry Pi power supply

## Optional

* Breadboard
* Multiple RFID cards/tags
* Enclosure
* LED
* Buzzer
* Network connection

---

# Wiring

The RC522 uses the Raspberry Pi's **SPI0** interface.

| RC522 Pin    | Raspberry Pi Physical Pin |        BCM GPIO | Purpose         |
| ------------ | ------------------------: | --------------: | --------------- |
| **VCC**      |                 **Pin 1** |               — | 3.3 V power     |
| **RST**      |                **Pin 22** |      **GPIO25** | Reset           |
| **GND**      |                 **Pin 6** |               — | Ground          |
| **IRQ**      |         **Not connected** |               — | Not required    |
| **MISO**     |                **Pin 21** |       **GPIO9** | SPI MISO        |
| **MOSI**     |                **Pin 19** |      **GPIO10** | SPI MOSI        |
| **SCK**      |                **Pin 23** |      **GPIO11** | SPI clock       |
| **SDA / SS** |                **Pin 24** | **GPIO8 / CE0** | SPI chip select |

### Wiring summary

```text
RC522                 Raspberry Pi Zero 2 W
------------------------------------------------

VCC   ─────────────── Pin 1  (3.3 V)

RST   ─────────────── Pin 22 (GPIO25)

GND   ─────────────── Pin 6  (GND)

IRQ   ─────────────── Not connected

MISO  ─────────────── Pin 21 (GPIO9)

MOSI  ─────────────── Pin 19 (GPIO10)

SCK   ─────────────── Pin 23 (GPIO11)

SDA   ─────────────── Pin 24 (GPIO8 / CE0)
```

## Important

The RC522 is a **3.3 V device**.

Connect:

```text
RC522 VCC → Raspberry Pi Pin 1
```

Do **not** connect the RC522 VCC to a 5 V pin.

The RC522 pin labelled `SDA` is being used as **SPI chip select / SS** in this configuration. It is not being used as I²C SDA.

---

# Raspberry Pi Setup

## 1. Update Raspberry Pi OS

Run:

```bash
sudo apt update
sudo apt upgrade -y
```

Reboot if necessary:

```bash
sudo reboot
```

---

# 2. Enable SPI

Run:

```bash
sudo raspi-config
```

Navigate to:

```text
Interface Options
    ↓
SPI
    ↓
Enable
```

Then reboot:

```bash
sudo reboot
```

---

# 3. Verify SPI

Run:

```bash
ls /dev/spidev*
```

Expected:

```text
/dev/spidev0.0
/dev/spidev0.1
```

The RFID reader uses:

```text
/dev/spidev0.0
```

because its SDA/SS pin is connected to CE0.

---

# Software Installation

## 1. Check Python

Run:

```bash
python3 --version
```

Python 3 should already be installed on Raspberry Pi OS.

---

## 2. Install `spidev`

Run:

```bash
sudo apt install -y python3-spidev
```

This allows Python to communicate with the RC522 over SPI.

---

## 3. Install `RPi.GPIO`

Run:

```bash
sudo apt install -y python3-rpi.gpio
```

This provides GPIO control for the RC522 reset pin.

---

## 4. Install Both Dependencies

They can also be installed together:

```bash
sudo apt update
sudo apt install -y python3-spidev python3-rpi.gpio
```

---

# Verify the Installation

Run:

```bash
python3 -c "import spidev; import RPi.GPIO; print('SPI and GPIO libraries OK')"
```

Expected:

```text
SPI and GPIO libraries OK
```

---

# Project Structure

The recommended project structure is:

```text
Scanner-Technology/
│
├── README.md
│
└── RFID/
    │
    ├── README.md
    ├── rfid_reader.py
    │
    └── read-cards/
        ├── 2026-08-29_01-42-15_001.txt
        ├── 2026-08-29_01-45-32_002.txt
        └── ...
```

The `read-cards/` directory does **not** need to be created manually.

The Python program automatically creates it when it starts.

---

# Running the Scanner

Navigate to the RFID directory:

```bash
cd ~/Scanner-Technology/RFID
```

Run:

```bash
python3 rfid_reader.py
```

The program should display:

```text
============================================================
              RFID-RC522 FULL SCAN LOGGER
============================================================

Scan files:
  /home/strato/Scanner-Technology/RFID/read-cards

Initialising RC522...
RC522 Version Register: 0x92
RC522 detected successfully.

RFID scanner is active.
Place an RFID card/tag on the reader.
Each scan will be saved as a separate file in read-cards/.

Press CTRL+C to stop.
```

Place an RFID card/tag onto the RC522.

A successful scan should produce something similar to:

```text
------------------------------------------------------------
SCAN ID       : 001
UID           : 04:A1:B2:C3
Card type     : MIFARE Classic 1K
Blocks read   : 64
Blocks failed : 0
Saved to      : read-cards/2026-08-29_01-42-15_001.txt
------------------------------------------------------------
```

---

# Scan File Storage

Every successful scan creates a **new file**.

The filename format is:

```text
YYYY-MM-DD_HH-MM-SS_SCANID.txt
```

For example:

```text
2026-08-29_01-42-15_001.txt
```

means:

| Component    | Meaning            |
| ------------ | ------------------ |
| `2026-08-29` | Scan date          |
| `01-42-15`   | Scan time          |
| `001`        | Scan ID            |
| `.txt`       | Scan record format |

Another scan might produce:

```text
2026-08-29_01-43-27_002.txt
```

The scan ID continues across program restarts.

For example, if the last scan before shutdown was:

```text
..._014.txt
```

the next scan will be:

```text
..._015.txt
```

---

# Information Captured

The scanner attempts to capture all information available through the RC522 for the detected card.

## Card identification

The scan record includes:

* UID
* UID length
* ATQA
* SAK
* Detected card type

## MIFARE Classic memory

For compatible MIFARE Classic cards, the program attempts to read:

* Sector number
* Block number
* Authentication status
* Raw hexadecimal block contents
* ASCII representation of block contents
* Failed reads
* Authentication failures

## Scan metadata

Each file also records:

* Scan ID
* Timestamp
* RFID reader
* SPI interface
* Reset GPIO
* Number of blocks attempted
* Number of blocks successfully read
* Number of failed blocks

---

# Example Scan File

A generated scan file will look approximately like:

```text
============================================================
                    RFID SCAN RECORD
============================================================

SCAN INFORMATION
------------------------------------------------------------
Scan ID       : 001
Timestamp     : 2026-08-29 01:42:15.234
Reader        : MFRC522 / RC522
Interface     : SPI0 / CE0
RST GPIO      : GPIO25

CARD INFORMATION
------------------------------------------------------------
Card type     : MIFARE Classic 1K
UID           : 04:A1:B2:C3
UID length    : 4 bytes
ATQA          : 00:04
SAK           : 0x08

RAW IDENTIFICATION DATA
------------------------------------------------------------
ATQA HEX      : 00 04
SAK HEX       : 08
UID HEX       : 04 A1 B2 C3

CARD MEMORY
------------------------------------------------------------

Sector 0 - Block 0
Authentication : SUCCESS
HEX             : 04 A1 B2 C3 12 08 04 00 62 63 64 65 66 67 68 69
ASCII           : ........bcdefghi

Sector 0 - Block 1
Authentication : SUCCESS
HEX             : ...
ASCII           : ....

...

SCAN SUMMARY
------------------------------------------------------------
Blocks attempted : 64
Blocks read      : 64
Blocks failed    : 0

============================================================
                      END OF SCAN
============================================================
```

The actual contents depend entirely on the RFID card.

---

# Duplicate Scan Prevention

The program does not continuously create files while a card remains sitting on the reader.

For example, this:

```text
Card placed on reader
       ↓
Scan 001
       ↓
Card remains on reader
       ↓
No additional scans
       ↓
Card removed
       ↓
Card placed on reader again
       ↓
Scan 002
```

This prevents hundreds of duplicate scan files from being generated when a card is left on the reader.

The current removal delay is:

```python
CARD_REMOVAL_DELAY = 1.0
```

---

# Important: Card Memory and Authentication

The RC522 cannot necessarily read every piece of information stored on every RFID card.

For example, a MIFARE Classic card contains authentication-protected sectors.

The program attempts to authenticate using the standard factory key:

```text
FF FF FF FF FF FF
```

If the sector uses a different key, the program records:

```text
Authentication : FAILED
```

rather than falsely reporting that the memory was empty.

This means a failed block does **not necessarily mean that no data exists in that block**. It may simply be protected by a key that the program does not have.

---

# Troubleshooting

## No `/dev/spidev0.0`

Check:

```bash
ls /dev/spidev*
```

If nothing appears:

```bash
sudo raspi-config
```

Enable:

```text
Interface Options
→ SPI
→ Enable
```

Then:

```bash
sudo reboot
```

---

## RC522 version is `0x00` or `0xFF`

Check:

* VCC
* GND
* MISO
* MOSI
* SCK
* SDA/SS
* RST

The critical SPI wiring is:

```text
MISO → Pin 21
MOSI → Pin 19
SCK  → Pin 23
SDA  → Pin 24
```

---

## `No module named 'spidev'`

Run:

```bash
sudo apt install -y python3-spidev
```

---

## `No module named 'RPi'`

Run:

```bash
sudo apt install -y python3-rpi.gpio
```

---

## RC522 initializes but card is not detected

Check:

1. The RC522 has 3.3 V power.
2. SPI is enabled.
3. The wiring matches the table.
4. The card/tag is placed directly over the RC522 antenna.
5. The RFID card is compatible with the RC522.
6. The RC522 module itself is functioning.

Run the scanner and check:

```text
RC522 Version Register: 0x92
```

or:

```text
RC522 Version Register: 0x91
```

A valid version response indicates that the Raspberry Pi is communicating with the RC522.

---

# Stopping the Scanner

Press:

```text
CTRL+C
```

The program will clean up the SPI and GPIO interfaces before exiting.

---

# Future Improvements

The current implementation is intentionally a basic standalone RFID data acquisition system.

Possible future additions include:

* Automatic startup using `systemd`
* SQLite database storage
* Web interface
* RFID card registration
* Card/user association
* Access control
* LED status indicator
* Buzzer
* REST API
* MQTT communication
* Network-based logging
* Multiple RFID readers
* Additional MIFARE authentication keys
* Support for additional RFID protocols
* Export tools for collected scan files

---

# Quick Setup

For an already configured Raspberry Pi:

```bash
cd ~/Scanner-Technology/RFID
```

Install dependencies:

```bash
sudo apt update
sudo apt install -y python3-spidev python3-rpi.gpio
```

Verify SPI:

```bash
ls /dev/spidev*
```

Run:

```bash
python3 rfid_reader.py
```

Place an RFID card/tag on the reader.

The resulting scan will automatically be saved under:

```text
read-cards/
```

with a filename such as:

```text
2026-08-29_01-42-15_001.txt
```
