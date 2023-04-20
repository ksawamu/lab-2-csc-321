# csc 321
# lab 2
# task 1
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode




BLOCKSIZE = AES.block_size
key = get_random_bytes(BLOCKSIZE)
iv = get_random_bytes(BLOCKSIZE)

def ecb_mode(plain):
    outfile = open("out.bmp", "wb")
    with open(plain, "rb") as f:
        binary_f = f.read()
        header = binary_f[:54]
        outfile. write(header)
        image = binary_f[54:]
        
        padded_plain = pad(image, AES.block_size, style='pkcs7')
        aes_obj = AES.new(key, AES.MODE_ECB)
        cipher_text = aes_obj.encrypt(padded_plain)
        outfile.write(cipher_text)
        
    outfile.close()


def cbc_mode(plain):


    outfile = open("out.bmp", "w")

    with open(plain, "rb") as f:
        header = plain[:54]
        outfile. write(header)
        image = plain[54:]
        padded_plain = pad(image , AES.block_size, style='pkcs7')

        aes_obj = AES.new(key, AES.MODE_ECB)
        for i in range(len(padded_plain)//BLOCKSIZE):
            current_block = padded_plain[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
            if (i == 0):
                current_block = current_block ^ iv
            else:
                current_block = current_block ^ previous_block
            cipher_text = aes_obj.encrypt(current_block)
            previous_block = cipher_text
            outfile.write(current_block)
            return outfile



def submit (user_input):
    new_string = "userid=456;userdata=" + user_input + ";session-id=31337"
    new_string = new_string.replace("=", "%3D")
    new_string = new_string.replace(";", "%3B")
    padded_input = pad(new_string , AES.block_size, style='pkcs7')
    return cbc_mode(padded_input)

def verify(encrypted_string):
    cipher = AES.new(key, AES.MODE_ECB)
    plain_text = unpad(cipher.decrypt(encrypted_string), AES.block_size)
    if ";admin=true;" in plain_text:
        return True
    else:
        return False



# 2) Ask about bit flipping for the admin=True thing

# 3) the openSSL
    # speed rsa
    # speed aes

ecb_mode("cp-logo.bmp")