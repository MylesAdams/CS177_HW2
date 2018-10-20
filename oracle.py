# CS177 -- padding oracle attacks This code is (unfortunately) meant
# to be run with Python 2.7.10 on the CSIL cluster
# machines. Unfortunately, cryptography libraries are not available
# for Python3 at present, it would seem.
from Crypto.Cipher import AES
import binascii
import sys

def check_enc(text):
    nl = len(text)
    val = int(binascii.hexlify(text[-1]), 16)
    if val == 0 or val > 16:
        return False

    for i in range(1,val+1):
        if (int(binascii.hexlify(text[nl-i]), 16) != val):
            return False
    return True
                                 
def PadOracle(ciphertext):
    if len(ciphertext) % 16 != 0:
        return False
    
    tkey = 'Sixteen byte key'

    ivd = ciphertext[:AES.block_size]
    dc = AES.new(tkey, AES.MODE_CBC, ivd)
    ptext = dc.decrypt(ciphertext[AES.block_size:])

    return check_enc(ptext)


# Padding-oracle attack comes here

if len(sys.argv) > 1:
    myfile = open(sys.argv[1], "r")
    ctext=myfile.read()
    myfile.close()

    # complete from here. The ciphertext is now (hopefull) stored in
    # ctext as a string. Individual symbols can be accessed as
    # ord(ctext[i]). Some more hints will be given on the Piazza
    # page.

    import copy

    def LLIntsToCT(LLInts, LastBlockIndex):
        CipherText = ''
        for LInts in LLInts[LastBlockIndex - 1:LastBlockIndex + 1]:
            for Int in LInts:
                CipherText = CipherText + chr(Int)
        return CipherText

    def LLIntsToAscii(LLInts):
        CipherText = ''
        for LInts in LLInts[1:]:
            for Int in LInts:
                CipherText = CipherText + chr(Int)
        return CipherText


    CTBlocks = [map(ord, list(ctext[i:i+16])) for i in range(0, len(ctext), 16)]

    PTBlocks = [None] * len(CTBlocks)
    for i in range(0, len(CTBlocks)):
        PTBlocks[i] = [0] * 16


    TempCTBlocks = copy.deepcopy(CTBlocks)

    for BlockNdx in reversed(range(1, len(CTBlocks))):
        TempCTBlocks[BlockNdx] = copy.deepcopy(CTBlocks[BlockNdx])
        XorBytes = [0] * 16
        for ByteNdx in reversed(range(0, 16)):
            PossibleValue = None

            XorByte = CTBlocks[BlockNdx - 1][ByteNdx]

            XorBytes[ByteNdx] = XorByte

            PossibleNewByte = None

            for NumGuess in range(0, 256):

                NewByte = XorByte ^ NumGuess ^ (16 - ByteNdx)

                TempCTBlocks[BlockNdx - 1][ByteNdx] = NewByte

                if (PadOracle(LLIntsToCT(TempCTBlocks, BlockNdx))):

                    if (PossibleValue is None and ByteNdx is 15):
                        PossibleValue = NumGuess
                        PossibleNewByte = copy.deepcopy(NewByte)
                    else:
                        PTBlocks[BlockNdx][ByteNdx] = NumGuess
                        TempCTBlocks[BlockNdx - 1][ByteNdx] = copy.deepcopy(NewByte)
                        break

            if (PossibleValue is not None):
                TempCTBlocks[BlockNdx - 1][14] += 1
                TempCTBlocks[BlockNdx - 1][14]

                if (PadOracle(LLIntsToCT(TempCTBlocks, BlockNdx)) is False):
                    PTBlocks[BlockNdx][ByteNdx] = PossibleValue
                    TempCTBlocks[BlockNdx - 1][ByteNdx] = copy.deepcopy(PossibleNewByte)


                TempCTBlocks[BlockNdx - 1][14] -= 1
                TempCTBlocks[BlockNdx - 1][14]

            for i in range(ByteNdx, 16):
                TempCTBlocks[BlockNdx - 1][i] = XorBytes[i] ^ PTBlocks[BlockNdx][i] ^ (17 - ByteNdx)

    print(LLIntsToAscii(PTBlocks))

    # end completing here, leave rest unchanged.
else:
    print("You need to specify a file!")
    

