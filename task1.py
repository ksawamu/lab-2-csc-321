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
block_cipher_text = []

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


# From https://techoverflow.net/2020/09/27/how-to-fix-python3-typeerror-unsupported-operand-types-for-bytes-and-bytes/
def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")




def cbc_mode(plain):
    outfile = open("out2.bmp", "wb")
    with open(plain, "rb") as f:
        binary_f = f.read()
        header = binary_f[:54]
        outfile. write(header)
        image = binary_f[54:]
        padded_plain = pad(image, AES.block_size, style='pkcs7')
        aes_obj = AES.new(key, AES.MODE_ECB)

        for i in range(len(padded_plain)//BLOCKSIZE):
            current_block = padded_plain[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
            if (i == 0):
                current_block = bitwise_xor_bytes(current_block, iv)
            else:
                current_block = bitwise_xor_bytes(current_block, previous_block)
            cipher_text = aes_obj.encrypt(current_block)
            previous_block = cipher_text
            outfile.write(cipher_text)
    return outfile


def cbc_mode_str(plain_str):
    outfile = open("out4.txt", "wb")
    aes_obj = AES.new(key, AES.MODE_ECB)
    for i in range(len(plain_str)//BLOCKSIZE):
        current_block = plain_str[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        if (i == 0):
            current_block = bitwise_xor_bytes(current_block, iv)
        else:
            current_block = bitwise_xor_bytes(current_block, previous_block)
        cipher_text = aes_obj.encrypt(current_block)
        previous_block = cipher_text
        outfile.write(bytes(cipher_text))
        block_cipher_text.append(bytes(cipher_text))
    return outfile

def print_bytes(block_num):
    current_block = block_cipher_text[block_num]
    print(current_block)

def print_bytes_all():
    for i in range(len(block_cipher_text)):
        print_bytes(i)


def submit (user_input):
    new_string = "userid=456;userdata=" + user_input + ";session-id=31337"
    new_string = new_string.replace("=", "%3D")
    new_string = new_string.replace(";", "%3B")
    padded_input = pad(bytes(new_string, "utf-8") , AES.block_size, style='pkcs7')

    return cbc_mode_str(padded_input)

def verify(encrypted_string):
    cipher = AES.new(key, AES.MODE_ECB)
    plain_text = unpad(cipher.decrypt(encrypted_string), AES.block_size)
    if ";admin=true;" in plain_text:
        return True
    else:
        return False



# 2) Ask about bit flipping for the admin=True thing
    # change the entire byte

# 3) the openSSL
    # speed rsa
    # speed aes
#ecb_mode("cp-logo.bmp")
# cbc_mode("cp-logo.bmp")
submit("8admin7true8")

print_bytes_all()
print("\n\n")
submit("8admin9true8")
print("\n\n")
print_bytes_all()
print("\n\n")