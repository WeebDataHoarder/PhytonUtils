# CRC notes

Uses 32-bit "MPEG2" polynomial 0x04C11DB7, data is fed in chunks of 4 bytes, little endian (swap order of each chunk bytes).

End chunk has to be padded with \x00 to fit into 4.