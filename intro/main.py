
'''
https://cryptohack.org/courses/intro/enc1/

values = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

ans = ''.join(chr(i) for i in values)

print(ans)
'''


'''
https://cryptohack.org/courses/intro/enc2/

hex_code = '63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d';

ans_bytes = bytes.fromhex(hex_code)

ans = ans_bytes.decode('utf-8') //Looked up this line in chatGPT

print(ans)
'''

'''
https://cryptohack.org/courses/intro/enc3/

import base64

hex_code = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'

ans_in_bytes = bytes.fromhex(hex_code)

ans = base64.b64encode(ans_in_bytes).decode('utf-8') 

print(ans)

'''

'''
https://cryptohack.org/courses/intro/enc4/

from Crypto.Util.number import *

# The given large integer
large_integer = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

# Converting the integer back into a message using long_to_bytes
message = long_to_bytes(large_integer).decode('utf-8')

# long_msg = bytes_to_long(message)
# print(long_msg)

print(message)

'''
'''
https://cryptohack.org/courses/intro/xor0/

from pwn import *

def xorOperation():
    result = xor(b'label',13).decode('utf-8');
    print(f'crypto{{{result}}}')

xorOperation()

'''