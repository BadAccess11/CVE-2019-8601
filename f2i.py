import struct
import sys
print(hex(int(sys.argv[1][2:], 16)))
bytes_ = struct.pack("<Q" ,int(sys.argv[1][2:], 16))
print(struct.unpack(">d", bytes_)[0])
