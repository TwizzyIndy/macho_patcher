import lief
import os

# put your local file addresses 
# (not same as global offset in Hex Editor) here
PATCH_ADDRESSES_LIST = [
  0x85f2c, # loc_100085f48
  0x23284, # loc_1000234f8
  0x47014, # loc_1000471d8
  0x53c60, # loc_100053d78
  0xbfe34, # loc_1000bff40
]

# put your desired patched bytes in list[list[int]] format

PATCH_BYTES_LIST = [
  [ 0xE0, 0x00, 0x00, 0x54 ], # b.eq loc_100085f48
  [ 0xAB, 0x13, 0x00, 0x54 ], # b.lt loc_1000234f8
  [ 0x2B, 0x0E, 0x00, 0x54 ], # b.lt loc_1000471d8
  [ 0xC0, 0x08, 0x00, 0x54 ], # b.eq loc_100053d78
  [ 0x60, 0x08, 0x00, 0x54 ], # b.eq loc_1000bff40
]

def patch(binary : lief.MachO.Binary, addr, patchBytes: list):
  # we only put the local addresses in this case, so we need to convert it to Virtual Address
  va_addr = binary.offset_to_virtual_address(addr)

  # patch the binary using the VA address with byte array
  binary.patch_address(va_addr,bytearray(patchBytes))

def main():
  if len(os.sys.argv) < 2:
    print('python3 macho_patcher.py [FILE_PATH]')
    return
  
  file = os.sys.argv[1]

  binary = lief.parse(file)

  for i, addr in enumerate(PATCH_ADDRESSES_LIST):
    patch(binary, addr, PATCH_BYTES_LIST[i])

  # removing signature
  binary.remove_signature()

  # write patched binary
  binary.write(f'{file}_patched')

  os.system(f'chmod 775 {file}_patched')

if __name__ == '__main__':
  main()
