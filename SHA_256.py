### python 3.6
### implementing: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
### variable names are derived from the variable names used in the description of SHA-256 in the link above
### written by Chris Langfield 

import sys
import numpy as np

inputString = sys.argv[1]

msgLength = 8 * len(inputString)

print(inputString)

msgArray = []

# list each character as an 8-bit integer
# note: unpackbits only works for uint8
for x in inputString:
    msgArray.append(np.unpackbits(np.uint8(ord(x))))
    
print('Message length in bits: ' + str(msgLength))

    ### PADDING THE MESSAGE

# -append 1 to the end of the message
msgArray.append(np.array([1],dtype=np.uint8))

# find the smallest k such that [(l + 65) + k] mod 512 = 0
k = 512 - ((msgLength+65)%512)
print('Padding message with ' + str(k) + ' zero bits.')
paddingZeros = [0 for x in range(k)]
msgArray.append(np.array(paddingZeros))

# finally, append the 64 bit representation of the length of the message
binReprMsgLength = format(msgLength,'b')
zerosToAdd64 = 64 - len(binReprMsgLength)
lastBits = [ 0 for x in range(zerosToAdd64) ]
for x in binReprMsgLength:
    lastBits.append(int(x))
msgArray.append(np.array(lastBits))
#print(msgArray)

    ### PRINT OUT THE PREPROCESSED MESSAGE
preprocMsg = ''
for a in msgArray:
    for x in np.nditer(a):
        preprocMsg += str(x)
for l in range(len(preprocMsg) // 32):
    print(str(l) + ' ' + str(preprocMsg[32*l:32*(l+1)]))
print('Length: ' + str(len(preprocMsg)) + ' bits')

    ### PARSE MESSAGE INTO N 512-bit BLOCKS
    ### AND EACH BLOCK INTO 15 32-bit WORDS
numBlocks = len(preprocMsg) // 512
print('Number of 512-bit blocks: ' + str(numBlocks))
blocks = [[0 for x in range(16)] for b in range(numBlocks)]
for b in range(numBlocks):
    for w in range(16):
        blocks[b][w] = preprocMsg[ b*512 + 32*w : b*512 + 32*(w+1)]    

    ### MAIN LOOP

initialHashValues = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,
                     0x9b05688c,0x1f83d9ab,0x5be0cd19]
intermediateHashValues = [0 for x in range(8)]
Register = {'a':0x00,
            'b':0x0,
            'c':0x0,
            'd':0x0,
            'e':0x0,
            'f':0x0,
            'g':0x0,
            'h':0x0
            }

T1 = 0x0
T2 = 0x0

# constants
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def circularShift(b, n):
    ### right-rotate 32 bit word b by integer n 
        unpacked = np.unpackbits(np.array([np.uint32(b)]).view(np.uint8)).reshape(-1,8)
        unpacked = np.flip(unpacked, 0)
        unpacked = unpacked.reshape(-1,32)
        unpacked = np.roll(unpacked, n)
        packed = np.packbits(unpacked.reshape(-1,4,8)[:,::-1]).view(np.uint32)
        return packed

### SHA-256 auxiliary functions

def Ch(e,f,g):
    e = np.uint32(e)
    f = np.uint32(f)
    g = np.uint32(g)
    eANDf = np.bitwise_and(e,f)
    NOTe = np.invert(e)
    NOTeANDg = np.bitwise_and(NOTe, g)
    return np.uint32(np.bitwise_xor(eANDf, NOTeANDg))
    
def Maj(a,b,c):
    a = np.uint32(a)
    b = np.uint32(b)
    c = np.uint32(c)
    aANDb = np.bitwise_and(a,b)
    aANDc = np.bitwise_and(a,c)
    bANDc = np.bitwise_and(b,c)
    return np.uint32(np.bitwise_xor(aANDb,np.bitwise_xor(aANDc,bANDc)))

def Sigma0(a):  
    return np.uint32(np.bitwise_xor(circularShift(a,2),
                          np.bitwise_xor(circularShift(a,13),circularShift(a,22))))
def Sigma1(a):    
    return np.uint32(np.bitwise_xor(circularShift(a,6),
                          np.bitwise_xor(circularShift(a,11),circularShift(a,25))))
def sigma0(a):
    return np.uint32(np.bitwise_xor(np.right_shift(a,3),
                          np.bitwise_xor(circularShift(a,7),circularShift(a,18))))
def sigma1(a):
    return np.uint32(np.bitwise_xor(np.right_shift(a,10),
                          np.bitwise_xor(circularShift(a,17),circularShift(a,19))))

# initialize hash values
intermediateHashValues[0] = np.uint32(initialHashValues[0])
intermediateHashValues[1] = np.uint32(initialHashValues[1])
intermediateHashValues[2] = np.uint32(initialHashValues[2])
intermediateHashValues[3] = np.uint32(initialHashValues[3])
intermediateHashValues[4] = np.uint32(initialHashValues[4])
intermediateHashValues[5] = np.uint32(initialHashValues[5])
intermediateHashValues[6] = np.uint32(initialHashValues[6])
intermediateHashValues[7] = np.uint32(initialHashValues[7])

for i in range(numBlocks):
    # update register with intermediate hashes
    Register['a'] = np.uint32(intermediateHashValues[0])
    Register['b'] = np.uint32(intermediateHashValues[1])
    Register['c'] = np.uint32(intermediateHashValues[2])
    Register['d'] = np.uint32(intermediateHashValues[3])
    Register['e'] = np.uint32(intermediateHashValues[4])
    Register['f'] = np.uint32(intermediateHashValues[5])
    Register['g'] = np.uint32(intermediateHashValues[6])
    Register['h'] = np.uint32(intermediateHashValues[7])
    # record past expanded message blocks
    exW_Array = [0x0 for l in range(64)]
    for j in range(64):
        # compute auxiliary functions and expanded message blocks
        _Ch = Ch(Register['e'],Register['f'],Register['g'])
        _Maj = Maj(Register['a'],Register['b'],Register['c'])
        _Sigma0 = Sigma0(Register['a'])
        _Sigma1 = Sigma1(Register['e'])
        if j < 16:
            exW = int('0b'+blocks[i][j],2)
        else:
            temp0 = np.uint32(np.mod(sigma1(exW_Array[j-2]) + exW_Array[j-7], 2**32))
            temp1 = np.uint32(np.mod(temp0 + sigma0(exW_Array[j-15]), 2**32))
            exW = np.uint32(np.mod(temp1 + exW_Array[j-16], 2**32))
        exW_Array[j] = exW

        # update register according to SHA-256 compression algorithm
  
        temp0 = np.uint32(np.mod((Register['h'] + _Sigma1), 2**32))
        temp1 = np.uint32(np.mod((temp0 + _Ch), 2**32))
        temp2 = np.uint32(np.mod((temp1 + K[j]), 2**32))
        T1 = np.uint32(np.mod((temp2 + exW), 2**32))
        T2 = np.uint32(np.mod((_Sigma0 + _Maj), 2**32))
        Register['h'] = Register['g']
        Register['g'] = Register['f']
        Register['f'] = Register['e']
        Register['e'] = np.uint32(np.mod((Register['d'] + T1), 2**32))[0]
        Register['d'] = Register['c']
        Register['c'] = Register['b']
        Register['b'] = Register['a']
        Register['a'] = np.uint32(np.mod((T1 + T2), 2**32))[0]

        # uncomment to print out intermediate register values
        
        #print('j = ' + str(j))
        #print('--------------------')
        #for r in Register:
            #print(r + ': ' + str(hex(Register[r])))
            
    intermediateHashValues[0] = np.mod((Register['a'] + intermediateHashValues[0]), 2**32)
    intermediateHashValues[1] = np.mod((Register['b'] + intermediateHashValues[1]), 2**32)
    intermediateHashValues[2] = np.mod((Register['c'] + intermediateHashValues[2]), 2**32)
    intermediateHashValues[3] = np.mod((Register['d'] + intermediateHashValues[3]), 2**32)
    intermediateHashValues[4] = np.mod((Register['e'] + intermediateHashValues[4]), 2**32)
    intermediateHashValues[5] = np.mod((Register['f'] + intermediateHashValues[5]), 2**32)
    intermediateHashValues[6] = np.mod((Register['g'] + intermediateHashValues[6]), 2**32)
    intermediateHashValues[7] = np.mod((Register['h'] + intermediateHashValues[7]), 2**32)


print()
print('final hash:')

outStr = ''

for h in range(8):
    outStr += str( hex(intermediateHashValues[h]))[2:]
    #print(hex(intermediateHashValues[h]))

print(outStr)
    
        
        

        
                         
        
        
    

        



    
    
