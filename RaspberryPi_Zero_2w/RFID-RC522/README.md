# RFID-RC522 Scanner

A lightweight RFID scanning system using an **MFRC522 (RC522) RFID reader** and a **Raspberry Pi Zero 2 W**.

The system continuously monitors the RFID reader, detects RFID card/tag UIDs, and records each detection with a timestamp in a CSV file.

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
* [Data Storage](#data-storage)
* [Duplicate Detection](#duplicate-detection)
* [Troubleshooting](#troubleshooting)
* [Future Improvements](#future-improvements)

---

# Overview

This project provides a basic, continuously running RFID scanner based on the **MFRC522 RFID module**.

The RC522 communicates with the Raspberry Pi Zero 2 W through the **SPI (Serial Peripheral Interface)** bus.

When an RFID card or tag enters the reader's detection range, the program:

1. Detects the RFID card/tag.
2. Reads its UID.
3. Generates a timestamp.
4. Stores the UID and timestamp in a CSV file.
5. Continues scanning for additional cards.

The system is designed as a simple foundation that can later be extended into an attendance system, access-control system, identification system, or other RFID-based application.

---

# Features

* Continuous RFID scanning
* MFRC522 / RC522 support
* Raspberry Pi Zero 2 W support
* SPI communication
* RFID UID detection
* Automatic timestamp generation
* CSV logging
* Duplicate-read protection
* Runs entirely locally
* No database required
* No internet connection required during operation
* Self-contained Python MFRC522 driver

---

# Technology Stack

| Category              | Technology            |
| --------------------- | --------------------- |
| Single-board computer | Raspberry Pi Zero 2 W |
| RFID reader           | MFRC522 / RC522       |
| RFID frequency        | 13.56 MHz             |
| RFID communication    | ISO/IEC 14443A        |
| Reader interface      | SPI                   |
| Operating system      | Raspberry Pi OS       |
| Programming language  | Python 3              |
| SPI library           | `spidev`              |
| GPIO library          | `RPi.GPIO`            |
| Data format           | CSV                   |
| Storage               | Local filesystem      |

---

# Hardware Requirements

## Required

* Raspberry Pi Zero 2 W
* MFRC522 / RC522 RFID reader
* RFID card or RFID tag
* Female-to-female jumper wires
* MicroSD card containing Raspberry Pi OS
* Raspberry Pi Zero 2 W power supply

## Optional

* Breadboard
* Additional RFID cards/tags
* Enclosure
* Status LED
* Buzzer
* External database/server

---

# Wiring

The RC522 is connected to the Raspberry Pi Zero 2 W using **SPI0 / CE0**.

## Pin Mapping

| RC522        | Raspberry Pi Physical Pin |        BCM GPIO | Function        |
| ------------ | ------------------------: | --------------: | --------------- |
| **VCC**      |                 **Pin 1** |               — | 3.3 V power     |
| **RST**      |                **Pin 22** |      **GPIO25** | Reset           |
| **GND**      |                 **Pin 6** |               — | Ground          |
| **IRQ**      |         **Not connected** |               — | Not required    |
| **MISO**     |                **Pin 21** |       **GPIO9** | SPI MISO        |
| **MOSI**     |                **Pin 19** |      **GPIO10** | SPI MOSI        |
| **SCK**      |                **Pin 23** |      **GPIO11** | SPI clock       |
| **SDA / SS** |                **Pin 24** | **GPIO8 / CE0** | SPI chip select |

### Wiring Diagram

```text
                 MFRC522
              ┌─────────────┐
              │             │
              │  VCC ───────┼──────── Pin 1  (3.3V)
              │  RST ───────┼──────── Pin 22 (GPIO25)
              │  GND ───────┼──────── Pin 6  (GND)
              │  IRQ        │
              │             │
              │  MISO ──────┼──────── Pin 21 (GPIO9)
              │  MOSI ──────┼──────── Pin 19 (GPIO10)
              │  SCK ───────┼──────── Pin 23 (GPIO11)
              │  SDA ───────┼──────── Pin 24 (GPIO8 / CE0)
              │             │
              └─────────────┘
```

## Important: 3.3 V Only

The RC522 module is a **3.3 V device**.

Connect:

```text
RC522 VCC → Raspberry Pi Pin 1 (3.3 V)
```

Do **not** connect VCC to:

```text
Pin 2  → 5 V
Pin 4  → 5 V
```

Doing so can damage the RC522.

### Note about `SDA`

The RC522 pin labelled:

```text
SDA
```

is commonly labelled this way because the module can support different communication interfaces.

In this project, the RC522 is operating in **SPI mode**, so:

```text
RC522 SDA / SS → Raspberry Pi GPIO8 / CE0
```

It is **not being used as I²C SDA**.

---

# Raspberry Pi Setup

Before running the Python program, the Raspberry Pi needs to have SPI enabled.

## 1. Update the Raspberry Pi

Run:

```bash
sudo apt update
sudo apt upgrade -y
```

A reboot may be required after major system updates:

```bash
sudo reboot
```

---

## 2. Enable SPI

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

Confirm the change.

Then reboot:

```bash
sudo reboot
```

---

## 3. Verify SPI

After reconnecting to the Raspberry Pi, run:

```bash
ls /dev/spidev*
```

Expected output:

```text
/dev/spidev0.0
/dev/spidev0.1
```

The RFID reader uses:

```text
/dev/spidev0.0
```

because the RC522 `SDA/SS` pin is connected to:

```text
GPIO8 / CE0
```

---

# Software Installation

The program requires Python 3 and two Python libraries.

There are two ways to install them:

1. Using Raspberry Pi OS packages — recommended.
2. Using `pip` — generally not necessary for this project.

The recommended installation uses the Raspberry Pi OS packages.

---

## 1. Check Python

Run:

```bash
python3 --version
```

You should receive something similar to:

```text
Python 3.x.x
```

---

## 2. Install SPI Support

Install the Python SPI library:

```bash
sudo apt install -y python3-spidev
```

This provides:

```python
import spidev
```

which allows Python to communicate with the RC522 over SPI.

---

## 3. Install GPIO Support

Install the Raspberry Pi GPIO library:

```bash
sudo apt install -y python3-rpi.gpio
```

This provides:

```python
import RPi.GPIO
```

which is used to control the RC522 reset pin.

---

## 4. Install Both Dependencies at Once

Alternatively, install both packages using:

```bash
sudo apt update
sudo apt install -y python3-spidev python3-rpi.gpio
```

---

## 5. Verify the Python Libraries

Run:

```bash
python3 -c "import spidev; import RPi.GPIO; print('SPI and GPIO libraries OK')"
```

Expected output:

```text
SPI and GPIO libraries OK
```

If this message appears, the Python dependencies are installed correctly.

---

# No RFID-Specific Package Required

This project does **not** require an external MFRC522 Python package.

The MFRC522 communication code is contained directly within:

```text
rfid_reader.py
```

This keeps the project self-contained and avoids depending on an external RFID library.

The only additional Python dependencies are:

```text
spidev
RPi.GPIO
```

---

# Project Structure

The recommended repository structure is:

```text
Scanner-Technology/
│
├── README.md
│
└── RFID/
    │
    ├── README.md
    └── rfid_reader.py
```

After the program is run for the first time, the following file will also be created:

```text
Scanner-Technology/
│
└── RFID/
    │
    ├── README.md
    ├── rfid_reader.py
    └── rfid_log.csv
```

---

# Running the Scanner

Navigate to the RFID directory:

```bash
cd ~/Scanner-Technology/RFID
```

Run the program:

```bash
python3 rfid_reader.py
```

The program should display:

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

Place an RFID card/tag near the RC522.

A successful detection should look similar to:

```text
[2026-08-29 01:30:15] RFID detected: 04:A1:B2:C3
```

---

# Data Storage

The scanner automatically creates:

```text
rfid_log.csv
```

The file uses the following format:

```csv
timestamp,uid
2026-08-29 01:30:15,04:A1:B2:C3
2026-08-29 01:31:02,93:7F:21:8A
```

## Data Fields

| Field       | Description                              |
| ----------- | ---------------------------------------- |
| `timestamp` | Date and time the RFID card was detected |
| `uid`       | UID of the RFID card/tag                 |

The CSV file is stored locally on the Raspberry Pi.

---

# Continuous Operation

The program is designed to remain active indefinitely.

While running, it repeatedly:

```text
      ┌─────────────────────┐
      │ Start RFID scanner  │
      └──────────┬──────────┘
                 │
                 ▼
      ┌─────────────────────┐
      │ Check for RFID tag  │
      └──────────┬──────────┘
                 │
          Card detected?
           /           \
         No             Yes
         │               │
         │               ▼
         │       ┌───────────────┐
         │       │ Read UID      │
         │       └───────┬───────┘
         │               │
         │               ▼
         │       ┌───────────────┐
         │       │ Add timestamp │
         │       └───────┬───────┘
         │               │
         │               ▼
         │       ┌───────────────┐
         │       │ Write CSV     │
         │       └───────┬───────┘
         │               │
         └───────────────┘
                 │
                 ▼
          Continue scanning
```

The scanner only stops when:

```text
CTRL+C
```

is pressed or the process is otherwise terminated.

---

# Duplicate Detection

An RFID reader can detect the same card repeatedly while it remains within range.

For example, without protection:

```text
04:A1:B2:C3
04:A1:B2:C3
04:A1:B2:C3
04:A1:B2:C3
04:A1:B2:C3
```

The program therefore uses a cooldown period.

The default is:

```python
READ_COOLDOWN = 2.0
```

This means the same UID will not be logged more than once every two seconds.

The value can be changed.

For example:

```python
READ_COOLDOWN = 5.0
```

would use a five-second cooldown.

---

# Stopping the Scanner

To stop the program normally:

```text
CTRL+C
```

The program will clean up the SPI and GPIO interfaces before exiting.

---

# Troubleshooting

## SPI device does not exist

Run:

```bash
ls /dev/spidev*
```

If nothing appears, enable SPI:

```bash
sudo raspi-config
```

Then:

```text
Interface Options → SPI → Enable
```

Reboot:

```bash
sudo reboot
```

---

## `No module named 'spidev'`

Install:

```bash
sudo apt install -y python3-spidev
```

Then verify:

```bash
python3 -c "import spidev; print('spidev OK')"
```

---

## `No module named 'RPi'`

Install:

```bash
sudo apt install -y python3-rpi.gpio
```

Then verify:

```bash
python3 -c "import RPi.GPIO; print('RPi.GPIO OK')"
```

---

## RC522 initializes but does not detect cards

Check every wire against the following table:

```text
VCC  → Pin 1
RST  → Pin 22
GND  → Pin 6
MISO → Pin 21
MOSI → Pin 19
SCK  → Pin 23
SDA  → Pin 24
```

`IRQ` should remain disconnected.

Also verify that the RC522 is receiving **3.3 V**, not 5 V.

---

## Program cannot access GPIO

Make sure the program is being run on the Raspberry Pi itself.

If necessary, test with:

```bash
python3 -c "import RPi.GPIO as GPIO; print(GPIO.VERSION)"
```

---

# Future Improvements

The current system intentionally provides only the basic RFID scanning functionality.

Possible future improvements include:

### Card Registration

Associate a UID with a specific person/device:

```text
04:A1:B2:C3 → Denzel Verster
```

### Database

Replace CSV storage with:

* SQLite
* MySQL/MariaDB
* PostgreSQL

### Attendance System

Record:

```text
Card UID
Person
Date
Time
Entry/Exit
```

### Access Control

Use the UID to determine whether access should be granted:

```text
RFID Card
    ↓
Read UID
    ↓
Check registered cards
    ↓
 ┌─────────────┐
 │ Authorized? │
 └──────┬──────┘
      Yes / No
       /     \
      ▼       ▼
   Allow     Deny
```

### Web Interface

Provide a web interface for viewing:

* Registered cards
* Scan history
* Users
* Access events
* Reader status

### Automatic Startup

Configure the scanner as a `systemd` service so that it automatically starts when the Raspberry Pi boots.

### Network Integration

Send RFID events to another system through:

* REST API
* MQTT
* TCP/IP
* WebSocket

---

# Summary

The complete setup consists of:

**Hardware**

```text
Raspberry Pi Zero 2 W
        │
        │ SPI
        ▼
    MFRC522
        │
        ▼
   RFID Card/Tag
```

**Software**

```text
Raspberry Pi OS
       │
       ▼
    Python 3
       │
   ┌───┴────┐
   ▼        ▼
spidev   RPi.GPIO
   │        │
   └───┬────┘
       ▼
    MFRC522
       │
       ▼
     UID
       │
       ▼
rfid_log.csv
```

### Minimum installation

For a fresh Raspberry Pi setup, the essential commands are:

```bash
sudo apt update
sudo apt install -y python3-spidev python3-rpi.gpio
```

Enable SPI:

```bash
sudo raspi-config
```

Then:

```text
Interface Options → SPI → Enable
```

Reboot:

```bash
sudo reboot
```

Verify:

```bash
ls /dev/spidev*
```

Expected:

```text
/dev/spidev0.0
/dev/spidev0.1
```

Run:

```bash
cd ~/Scanner-Technology/RFID
python3 rfid_reader.py
```

The scanner will then continuously monitor the RC522 and record detected RFID UIDs in `rfid_log.csv`.
