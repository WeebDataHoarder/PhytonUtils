# Phyton Utils

These are utilities and documentation for devices commonly released by [Phyton / Фитон](https://www.phyton.ru/), [AlmaCode](https://almacode.ru/), [AngioCode](https://angiocode.ru/), [RadiaCode](https://www.radiacode.com/);
a group of Russian companies that provide embedded devices for healthcare, industrial and military applications.

Most of their products, software or hardware, are undocumented and/or heavily obfuscated, encrypted, or worse.

These utilities allow researchers to inspect the devices and work with them directly, allowing, between others:
* Decoding of Firmware files, both `Phyton` format and `AlmaCode` format
* Decryption of Firmware Blocks
* Encryption of Firmware Blocks
* Decryption of device unique id encrypted code blocks in ROM
* Decompression of Custom compressed data
* Compression to Custom compressed data
* Calculate custom CRC of data
* Decryption of device Memory dumps
* Custom Firmware files
* Device debugging, repair, unbricking
* Decode `RD_FLASH_AREA` messages

### Disclaimers

Note this repository does not include code to communicate with devices via either USB or Bluetooth.
Other projects are available for that purpose.

All information and data in this repository was produced without physical disassembly of devices,
using publicly available information, files and software. 

### Tested devices and firmwares
* RadiaCode RC-102

## Documentation

Some items have been written in text form. For others, please refer to the source code.

* [Encryption notes](doc/ENCRYPTION.md)
* [Compression notes](doc/COMPRESSION.md)
* [Firmware notes](doc/FIRMWARE.md)
* [CRC notes](doc/CRC.md)