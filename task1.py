# csc 321
# lab 2
# task 1
#from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes




BLOCKSIZE = AES.block_size

def ecb_mode(plain):
   
    key = get_random_bytes(BLOCKSIZE)
    iv = get_random_bytes(BLOCKSIZE)
    
    #read plain text as binary
    with open(plain, "rb") as f:
        padded = pad(f , AES.block_size, style='pkcs7')
        aes_obj = AES.new(key, AES.MODE_ECB)
        cipher_text = aes_obj.encrypt(bytes(padded), "UTF-8")
        # create an AES Object to encrypt in ECB mode
        #write out E to append to a file here?
      
        
    
    # ecb
    # write encyption of plaintext in a new file
    outfile = open("out.txt", "w")


def cbc_mode(plain):
    # cbc
    pass
