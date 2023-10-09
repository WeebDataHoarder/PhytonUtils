# CRC notes

Uses 32-bit "MPEG2" polynomial _0x04C11DB7_, data is fed in chunks of 4 bytes,
little endian (swap order of each chunk bytes). There is no pre or post inversion. Start value is _0xFFFFFFFF_.

End chunk has to be padded with \x00 to fit into 4.