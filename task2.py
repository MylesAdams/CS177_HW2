#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import os

CipherTextStr = 'FFBC1ADC607ACDDEAE7D837FA8123A3A9CFDD83A9CD55F15A8CD7F8CFA32A67B'
CipherTextList = list(CipherTextStr)
print(CipherTextList)
CipherTextBytes = bytes.fromhex(CipherTextStr)
print(binascii.hexlify(CipherTextBytes))
print(binascii.hexlify(CipherTextBytes[15:16]))
print(CipherTextStr[30:32])
LastIVByte = int(CipherTextStr[30:32], 16)
print(LastIVByte)
NewLastIVByteInt = LastIVByte ^ 8 ^ 1
print(NewLastIVByteInt)
NewLastIVByteStr = hex(NewLastIVByteInt)[2:4]
CipherTextList[30] = NewLastIVByteStr[0]
CipherTextList[31] = NewLastIVByteStr[1]
print(''.join(CipherTextList))

def PadAttackStr32B(CipherText: str) -> str:
    assert(len(CipherText) == 64)

    CTByteList = [CipherText[2*i:2*(i+1)] for i in range(0, len(CipherText)//2)]

    NewByteInt = int(CTByteList[15], 16) ^ 8 ^ 1

    CTByteList[15] = hex(NewByteInt)[2:4]

    return ''.join(CTByteList)


if __name__ == "__main__":
    InitialValue = os.urandom(16)
    Key = os.urandom(16)
    Encryptor = AES.new(Key, AES.MODE_CBC, iv=InitialValue)
    PlainText = os.urandom(8) + (b'\x08') * 8
    print(binascii.hexlify(PlainText))
    CipherText = Encryptor.encrypt(PlainText)
    FullCipherText = InitialValue + CipherText
    print(FullCipherText)
    ModifiedCipherText = PadAttackStr32B(binascii.hexlify(FullCipherText).decode('utf-8'))

    Decryptor = AES.new(Key, AES.MODE_CBC, iv=InitialValue)
    RecoveredPlainText = Decryptor.decrypt(bytes.fromhex(ModifiedCipherText))
    print(binascii.hexlify(RecoveredPlainText[16:32]))
