# RFID-RC522 Scanner — Raspberry Pi Zero 2 W

A Python-based RFID scanning and logging system using the **MFRC522 / RC522 RFID reader** with a **Raspberry Pi Zero 2 W**.

The program detects ISO14443A-compatible RFID cards/tags, retrieves the information that the RC522/library can successfully access, and stores each scan as an individual timestamped text file.

---

## Features

* RFID card/tag detection using the RC522.
* UID extraction.
* UID length detection.
* RFID request/type information.
* Raw UID representation.
* MIFARE Classic memory-access attempts.
* Authentication status reporting.
* Individual scan files.
* Timestamped scan filenames.
* Persistent scan numbering.
* Human-readable scan reports.
* **One physical card placement = one scan.**
* Card remains locked until physical removal.
* No repeated scan output while a card remains on the reader.
* Silent polling while waiting for a card.
* Automatic GPIO/SPI cleanup when the program exits.

---

# Hardware

## Required Hardware

| Component                    | Quantity | Purpose                       |
| ---------------------------- | -------: | ----------------------------- |
| Raspberry Pi Zero 2 W        |        1 | Main computer                 |
| MFRC522 / RC522 RFID module  |        1 | RFID reader                   |
| RFID card/tag                |       1+ | Card/tag to test              |
| Jumper wires                 |       7+ | Connections                   |
| MicroSD card                 |        1 | Raspberry Pi operating system |
| 5V Raspberry Pi power supply |        1 | Power                         |

The RC522 should be powered from **3.3 V**.

> **Important:** Do not connect the RC522 VCC to the Raspberry Pi's 5 V pin.

---

# RC522 → Raspberry Pi Zero 2 W Wiring

The current program uses **SPI0 CE0**.

| RC522 Pin    | Raspberry Pi Pin | Raspberry Pi Function |
| ------------ | ---------------: | --------------------- |
| **VCC**      |            Pin 1 | 3.3 V                 |
| **RST**      |           Pin 22 | GPIO25                |
| **GND**      |            Pin 6 | Ground                |
| **MISO**     |           Pin 21 | GPIO9 / SPI0 MISO     |
| **MOSI**     |           Pin 19 | GPIO10 / SPI0 MOSI    |
| **SCK**      |           Pin 23 | GPIO11 / SPI0 SCLK    |
| **SDA / SS** |           Pin 24 | GPIO8 / SPI0 CE0      |
| **IRQ**      |    Not connected | —                     |

### Wiring summary

```text
                 RC522
              ┌───────────┐
              │           │
3.3V ─────────┤ VCC       │
GND  ─────────┤ GND       │
GPIO25 ───────┤ RST       │
GPIO9  ───────┤ MISO      │
GPIO10 ───────┤ MOSI      │
GPIO11 ───────┤ SCK       │
GPIO8  ───────┤ SDA / SS  │
              │ IRQ       │──── Not connected
              └───────────┘
```

---

# Software Requirements

## Operating System

The project is intended for:

* Raspberry Pi OS
* Raspberry Pi Zero 2 W
* Python 3

The Raspberry Pi must have SPI enabled.

---

# 1. Update the Raspberry Pi

Run:

```bash
sudo apt update
sudo apt upgrade -y
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
    → SPI
        → Enable
```

Then reboot:

```bash
sudo reboot
```

After reconnecting through SSH, verify SPI:

```bash
ls /dev/spidev*
```

You should normally see:

```text
/dev/spidev0.0
/dev/spidev0.1
```

The RFID program uses:

```text
SPI0 CE0
/dev/spidev0.0
```

---

# 3. Install Required Packages

Install the required system packages:

```bash
sudo apt update
sudo apt install -y python3-pip python3-dev python3-spidev
```

Install the GPIO library:

```bash
sudo apt install -y python3-rpi.gpio
```

The project uses the Python MFRC522 library.

If the `mfrc522` module is not already installed, install the required library according to the version used by the project.

Verify that Python can import the modules:

```bash
python3 -c "import RPi.GPIO; print('RPi.GPIO OK')"
```

and:

```bash
python3 -c "import spidev; print('spidev OK')"
```

Finally:

```bash
python3 -c "import mfrc522; print('MFRC522 library OK')"
```

If all three commands succeed, the Python environment can access the required modules.

---

# 4. Project Structure

The RFID scanner directory should look similar to:

```text
RFID-RC522/
│
├── README.md
├── read_rfid.py
│
└── scans/
    ├── 2026-08-29_03-31-37_005.txt
    ├── 2026-08-29_03-35-12_006.txt
    └── ...
```

The `scans/` directory is created automatically by the program if it does not already exist.

---

# Running the Scanner

From the RFID project directory:

```bash
cd ~/Scanner-Technology/RaspberryPi_Zero_2w/RFID-RC522
```

Run:

```bash
sudo python3 read_rfid.py
```

You should see:

```text
============================================================
              RFID-RC522 CARD LOGGER
============================================================

RFID SCANNER ACTIVE

Place one RFID card/tag on the reader.

IMPORTANT:
  One physical card placement = ONE scan.
  The same card will NOT be scanned again
  until it has been physically removed.

Press CTRL+C to stop.
```

Place the RFID card/tag directly on the RC522.

---

# Scan Behaviour

The scanner deliberately uses a **card-lock mechanism**.

The intended sequence is:

```text
WAITING
   │
   ▼
CARD DETECTED
   │
   ▼
Read UID / card information
   │
   ▼
Attempt available memory access
   │
   ▼
Save scan to TXT file
   │
   ▼
CARD LOCKED
   │
   │
   │  Card remains on reader
   │  No additional scans occur
   │
   ▼
CARD REMOVED
   │
   ▼
CARD LOCK RELEASED
   │
   ▼
WAITING FOR NEXT CARD
```

### Important

The reader continuously checks whether a card is present internally, but **these checks do not generate terminal messages or additional scan files**.

Therefore:

> Holding one card over the reader for five seconds should still produce only **one scan**.

The card must be physically removed before another scan can occur.

---

# Terminal Output

The terminal provides detailed information for an actual scan.

Example:

```text
============================================================
                    CARD DETECTED
============================================================

Scan ID       : 005
Timestamp     : 2026-08-29 03:31:37.592
UID           : 02:3C:B6:AB:23
UID length    : 5 bytes
Tag type      : 0x10 (PICC_REQALL / ISO14443A)
Raw UID       : [2, 60, 182, 171, 35]
```

The program then attempts to access supported card memory.

For example:

```text
------------------------------------------------------------
              MIFARE CLASSIC MEMORY READ
------------------------------------------------------------

Card type assumption : MIFARE Classic 1K
Sectors              : 16
Blocks per sector    : 4
Total blocks         : 64
Key A                : FF FF FF FF FF FF
```

If authentication fails, the program records the failure rather than pretending that memory was successfully read.

---

# Scan Files

Every accepted scan creates a separate file inside:

```text
scans/
```

The filename format is:

```text
YYYY-MM-DD_HH-MM-SS_ID.txt
```

For example:

```text
2026-08-29_03-31-37_005.txt
```

Where:

| Component    | Meaning              |
| ------------ | -------------------- |
| `2026-08-29` | Scan date            |
| `03-31-37`   | Scan time            |
| `005`        | Scan sequence number |

---

# Scan File Contents

A scan file contains the information successfully obtained during that particular scan.

A typical file contains sections such as:

```text
============================================================
                    RFID SCAN RECORD
============================================================

[SCAN INFORMATION]
------------------------------------------------------------
Scan ID              : 005
Timestamp            : 2026-08-29 03:31:37.592
Reader               : MFRC522 / RC522
SPI Interface        : SPI0 CE0

[CARD IDENTIFICATION]
------------------------------------------------------------
UID                  : 02:3C:B6:AB:23
UID HEX              : 02 3C B6 AB 23
UID Length           : 5 bytes
Tag Type             : 0x10 (PICC_REQALL / ISO14443A)

[RAW UID DATA]
------------------------------------------------------------
02 3C B6 AB 23

[CARD MEMORY]
------------------------------------------------------------
...
```

Memory information is recorded only when the RC522/library successfully obtains it.

---

# Understanding Authentication Failures

A common result with RFID cards is:

```text
AUTHENTICATION FAILED
```

This does **not** mean that the RC522 failed to detect the card.

There are two separate operations:

```text
RFID DETECTION
       ↓
Card detected
       ↓
UID obtained
```

and:

```text
MEMORY ACCESS
       ↓
Authentication required
       ↓
Memory may or may not be readable
```

Therefore, it is possible to successfully obtain:

```text
UID : 02:3C:B6:AB:23
```

while obtaining:

```text
Blocks successfully read : 0
Authentication failures   : 16
```

This indicates that the reader detected the card but could not authenticate to the protected MIFARE Classic sectors using the key configured by the program.

---

# What the RC522 Can and Cannot Read

The RC522 is a **13.56 MHz RFID/NFC reader**, not a universal RFID reader.

The actual information available depends on the card/tag technology.

The scanner attempts to record everything that the connected hardware and software can legitimately retrieve, including:

* UID
* UID length
* Request/type information
* Raw UID bytes
* Card selection status
* Accessible memory blocks
* Memory block hexadecimal data
* Printable ASCII representation
* Authentication results
* Read failures
* Scan timestamp
* Scan number

However, the program cannot automatically obtain information that the RFID technology does not expose or that is protected by authentication.

---

# Important MIFARE Classic Note

For MIFARE Classic cards, memory is divided into sectors and blocks.

A MIFARE Classic 1K card contains:

```text
16 sectors
4 blocks per sector
64 blocks total
```

Each block contains:

```text
16 bytes
```

The final block of each sector is a sector trailer containing access-control information and keys.

The scanner may therefore report authentication failures even though the card itself is functioning correctly.

The default key attempted by the current program is:

```text
FF FF FF FF FF FF
```

If a sector uses a different key, the program will not be able to read that protected sector using this key.

---

# Viewing Previous Scans

List scan files:

```bash
ls scans
```

Read the most recent files:

```bash
cat scans/2026-08-29_03-31-37_005.txt
```

Or use:

```bash
less scans/2026-08-29_03-31-37_005.txt
```

To search for a particular value:

```bash
grep -i "UID" scans/*.txt
```

---

# Clearing Previous Scan Files

If the scan directory needs to be cleared:

```bash
sudo rm -rf scans
```

The program will automatically recreate it on the next run.

> Be careful with `rm -rf`. Make sure the path is exactly the project `scans` directory before executing it.

---

# Stopping the Program

Press:

```text
CTRL+C
```

The program will terminate and clean up the GPIO resources.

Expected output:

```text
============================================================
Stopping RFID scanner...
============================================================

GPIO cleaned up.
RFID scanner stopped.
```

---

# Troubleshooting

## RC522 is not detected

Check the wiring first.

Verify:

```text
VCC  → 3.3V
GND  → GND
SDA  → GPIO8 / CE0
SCK  → GPIO11
MOSI → GPIO10
MISO → GPIO9
RST  → GPIO25
```

Then check SPI:

```bash
ls /dev/spidev*
```

You should see:

```text
/dev/spidev0.0
```

---

## RC522 Version Register is 0x92

A result such as:

```text
RC522 Version Register: 0x92
```

indicates that the RC522 is responding over SPI.

This is a good indication that:

* The module is powered.
* SPI communication is working.
* The Raspberry Pi can communicate with the RC522.

---

## UID is detected but memory cannot be read

Example:

```text
UID : 02:3C:B6:AB:23

Blocks successfully : 0
Authentication failed : 16
```

This means the reader can detect the card and obtain its UID, but the attempted memory authentication was unsuccessful.

This is not necessarily a wiring problem.

---

## The same card is scanned repeatedly

The intended program behaviour is:

```text
CARD DETECTED
     ↓
ONE SCAN
     ↓
CARD LOCKED
     ↓
WAIT
     ↓
PHYSICAL REMOVAL
     ↓
CARD UNLOCKED
```

If the same UID is being saved repeatedly without physically removing the card, the card-lock/removal logic in `read_rfid.py` should be checked.

---

## Terminal output repeats authentication errors

Authentication errors are expected when a sector cannot be authenticated.

The program should report each sector **once during the single scan**.

It should not continuously repeat the entire scan while the card remains on the reader.

---

# Git

The project is stored in:

```text
DSVerster/Scanner-Technology
```

To update the Raspberry Pi copy:

```bash
cd ~/Scanner-Technology
git pull origin main
```

Then enter the RFID project:

```bash
cd RaspberryPi_Zero_2w/RFID-RC522
```

Run the scanner:

```bash
sudo python3 read_rfid.py
```

---

# Project Purpose

This project forms part of the RFID/scanner technology work for the Raspberry Pi Zero 2 W platform.

The scanner is designed primarily for **RFID detection, data acquisition, experimentation, and logging**.

The scan files provide a persistent record of what the RC522 was able to obtain from each individual RFID interaction.

---

## Quick Start

For subsequent uses, the basic procedure is simply:

```bash
cd ~/Scanner-Technology
git pull origin main

cd RaspberryPi_Zero_2w/RFID-RC522

sudo python3 read_rfid.py
```

Then:

```text
1. Place ONE card/tag on the RC522.
2. Wait for CARD DETECTED.
3. Allow the scan to finish.
4. The scan is saved automatically.
5. Remove the card.
6. Wait for CARD REMOVED.
7. Place the next card/tag on the reader.
```

**One card placement → one scan file.**
