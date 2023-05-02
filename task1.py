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
global_cipher_text = b""

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
def bitwise_and_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") & int.from_bytes(b, byteorder="big")
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


def cbc_mode_str(padded_str):
    aes_obj = AES.new(key, AES.MODE_ECB)
    temp_cipher_text = b""
    for i in range(len(padded_str)//BLOCKSIZE):
        current_block = padded_str[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        if (i == 0):
            current_block = bitwise_xor_bytes(current_block, iv)
        else:
            current_block = bitwise_xor_bytes(current_block, previous_block)
        cipher_text = aes_obj.encrypt(current_block)

        temp_cipher_text += cipher_text
        previous_block = cipher_text
        block_cipher_text.append(bytes(cipher_text))
    global_cipher_text = temp_cipher_text
    return global_cipher_text

def print_bytes(block_num):
    current_block = block_cipher_text[block_num]
    print(current_block)

def print_bytes_all():
    for i in range(len(block_cipher_text)):
        print_bytes(i)


def submit (user_input):
    new_string = "userid=456;userdata=" + user_input + ";session-id=31337"
    padded_input = pad(bytes(new_string, "utf-8") , AES.block_size, style='pkcs7')
    return cbc_mode_str(padded_input)

def verify(encrypted_string):
    encrypted_list = []
    i = 0
    while (i < len(encrypted_string)):
        encrypted_list.append(bytes(encrypted_string[i: i +16]))
        i += 16
    
    cipher = AES.new(key, AES.MODE_ECB)

    plain_text = b""
    for i in range(len(encrypted_list) - 1, -1, -1):
        if i == len(encrypted_list) - 1:
            decrypted = cipher.decrypt(encrypted_list[i])
        else:
            decrypted = cipher.decrypt(encrypted_list[i])
        if i != 0:
            plain_text = bitwise_xor_bytes(encrypted_list[i - 1], decrypted) + plain_text
        else:
            plain_text = bitwise_xor_bytes(iv, decrypted) + plain_text
    print("this is plain_text in verify(): ", plain_text)
    if bytes(";admin=true;", "utf-8") in plain_text:
        return True
    else:
        return False

def hack_verify(encrypted_string):
    
    encrypted_list = []
    i = 0
    while (i < len(encrypted_string)):
        encrypted_list.append(bytes(encrypted_string[i: i +16]))
        i += 16
    print("original encrypted_string:")
    print(encrypted_string)
    
    new_encrypted_string_without_xor = encrypted_list[0] + encrypted_list[1] + encrypted_list[2] + encrypted_list[3]
    print("encrypted string without xor: ", new_encrypted_string_without_xor)
  
    new_encrypted_string = encrypted_list[0][0:4]
    new_encrypted_string += bitwise_xor_bytes(bitwise_xor_bytes((encrypted_list[0][4]).to_bytes(1, "big"), b"\x3B"), b"\x38")
    new_encrypted_string += encrypted_list[0][5:10]
    new_encrypted_string += bitwise_xor_bytes(bitwise_xor_bytes((encrypted_list[0][10]).to_bytes(1, "big"), b"\x3D"), b"\x37")
    new_encrypted_string += encrypted_list[0][11:15]
    new_encrypted_string += bitwise_xor_bytes(bitwise_xor_bytes((encrypted_list[0][15]).to_bytes(1, "big"), b"\x3B"), b"\x38")
    
    print("this is what new_encrypted_string is: ", new_encrypted_string)
    
    # # set the rest of new_encrypted_string
    i = 1
    while (i < len(encrypted_list)):
        new_encrypted_string += encrypted_list[i]
        i += 1
    print("complete hacked_encrypted string:")
    print(new_encrypted_string)
    return new_encrypted_string
    

# ecb_mode("mustang.bmp")
# cbc_mode("mustang.bmp")
# submit("8admin7true8") #8admin7true8



"""
userid=456;userd
ata=8admin7true8
; 000000000
session-id=31337 000000
"""


# print(verify(submit(";admin=true;")))
print("this is output from nested verify: ", verify(hack_verify(submit("8admin7true8"))))
