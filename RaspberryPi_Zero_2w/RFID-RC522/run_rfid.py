import spidev
import RPi.GPIO as GPIO
import time

RST_PIN = 25

GPIO.setmode(GPIO.BCM)
GPIO.setup(RST_PIN, GPIO.OUT)

GPIO.output(RST_PIN, GPIO.HIGH)

spi = spidev.SpiDev()
spi.open(0, 0)

spi.max_speed_hz = 1000000
spi.mode = 0

def read_register(address):
    response = spi.xfer2([
        ((address << 1) & 0x7E) | 0x80,
        0x00
    ])

    return response[1]

print("Testing RC522...")
print()

# MFRC522 VersionReg = 0x37
version = read_register(0x37)

print(f"Version register: 0x{version:02X}")

if version in [0x91, 0x92]:
    print("RC522 detected successfully.")

elif version == 0x88:
    print("FM17522/compatible reader detected.")

elif version == 0x00:
    print("No response from RC522.")
    print("Check wiring, power and SPI.")

elif version == 0xFF:
    print("No valid SPI response.")
    print("Check wiring and SPI configuration.")

else:
    print("Unexpected value.")
    print("The RC522 may not be communicating correctly.")

spi.close()
GPIO.cleanup()