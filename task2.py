#!/usr/bin/env python3

from Crypto.Cipher import AES
import binascii
import os


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

    CipherText = Encryptor.encrypt(PlainText)
    FullCipherText = InitialValue + CipherText
    ModifiedCipherText = PadAttackStr32B(binascii.hexlify(FullCipherText).decode('utf-8'))

    Decryptor = AES.new(Key, AES.MODE_CBC, iv=InitialValue)
    RecoveredPlainText = Decryptor.decrypt(binascii.unhexlify(ModifiedCipherText))
    print('Original PlainText:', binascii.hexlify(PlainText))
    print('Modified PlainText:', binascii.hexlify(RecoveredPlainText[16:32]))
    print(binascii.hexlify(Decryptor.decrypt(os.urandom(32))))
