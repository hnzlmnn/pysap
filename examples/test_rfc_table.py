import pysapcompress

data = "\x86\x49\x9f\xd2\x41\x53\xed\xf0\xfd\xdd\x6f\xff\xae\xac\x85\x16" \
"\x5c\xc1\x9b\x8b\xc2\x15\x0c\x10\xeb\x04\x1a\x88\x37\x8f\xa0\xc1" \
"\x79\x05\x0d\x24\x44\x68\xb0\x60\xbc\x83\x07\x0d\x12\x5c\x58\x50" \
"\x1d\x3a\x75\x71\xd0\x69\x8c\xd3\xd1\xdc\x46\x74\xe6\xe2\xac\x53" \
"\x77\xb1\xa4\xc6\x8b\x1c\x45\xa2\x03\x09\x32\x23\x48\x8e\x20\x57" \
"\x76\xc4\xc8\xf1\xa5\x4d\x8e\x71\x44\xde\x64\xd9\xd3\xdc\xcb\x9f" \
"\x31\x75\x0e\x35\x27\xb2\xa8\xce\xa3\x43\x6b\xaa\xa4\xa9\xf1\xa3" \
"\xff\xc6\x90\x31\x83\x62\xfc\xa8\xee\xe7\x54\xa3\x45\x67\x1a\x8d" \
"\x43\x8e\x0e\x08\x72\x20\xc4\xd2\xf9\x56\xf6\x03\x04\x03\x04\x00" \
"\xff\x5b"

pysapcompress.decompress(data, 19641)
