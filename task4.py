#!/usr/bin/env python3

from Crypto.Cipher import AES
import binascii
import os

CipherText1 = '43371380524753188fd571d8622ae61f64ccb551d9b348119adbc410cbdef77cf180f7529d0da0c6f0a4fdb28a3d56e2105c7eb4b13b8c4cd9001523ba1e55dc2cd5608e84c093cd21d1126ddac1e7b2a5e9'

CipherText2 = '853b56f79857359cad582eb6e6cb1a23b9a08d1c32e8638da8067144b9d781795a0a79496ca15ffe8865408aa83194df66d87eb4b13b8c4cd9001523ba1e55dc2cd5608e84c093cd21d1126ddac1e7b2a5e9'

print(CipherText1[-64:] == CipherText2[-64:])
print(CipherText1[-64:])
print(CipherText2[-64:])

