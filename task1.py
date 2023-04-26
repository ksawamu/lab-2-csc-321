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


def cbc_mode_str(plain_str):
    outfile = open("out4.txt", "wb")
    aes_obj = AES.new(key, AES.MODE_ECB)
    temp_cipher_text = b""
    for i in range(len(plain_str)//BLOCKSIZE):
        current_block = plain_str[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        if (i == 0):
            current_block = bitwise_xor_bytes(current_block, iv)
        else:
            current_block = bitwise_xor_bytes(current_block, previous_block)
        cipher_text = aes_obj.encrypt(current_block)
        temp_cipher_text += cipher_text
        previous_block = cipher_text
        outfile.write(bytes(cipher_text))
        block_cipher_text.append(bytes(cipher_text))
    global_cipher_text = temp_cipher_text
    return global_cipher_text #this used to be the outfile, lol

def print_bytes(block_num):
    current_block = block_cipher_text[block_num]
    print(current_block)

def print_bytes_all():
    for i in range(len(block_cipher_text)):
        print_bytes(i)


def submit (user_input):
    new_string = ";admin=true;sdfsdfsdfsdfsdfsdfsdfsdfsdf"#"userid=456;userdata=" + user_input + ";session-id=31337"
    #new_string = new_string.replace("=", "%3D")
    #new_string = new_string.replace(";", "%3B")
    padded_input = pad(bytes(new_string, "utf-8") , AES.block_size, style='pkcs7')
    print(padded_input)

    return cbc_mode_str(padded_input)

def verify(encrypted_string):
    print("encrypted_string")
    print(encrypted_string)
    encrypted_list = []
    i = 0
    print(len(encrypted_string))
    while (i < len(encrypted_string)):
        encrypted_list.append(bytes(encrypted_string[i: i +16]))
        i += 16
    print("encrypted_list: ")
    print(encrypted_list)
        
    cipher = AES.new(key, AES.MODE_ECB)
    i = len(encrypted_list)
    plain_text = b""
    print(len(encrypted_list))
    for i in range(len(encrypted_list) - 1, 0, -1):
        if i == len(encrypted_list) - 1:
            print(encrypted_list[i])
            print(len(encrypted_list[i]))
            # start to see if can decrypt to see if it matches the
            # b'userid%3D456%3Buserdata%3D8admin7true8%3Bsession-id%3D31337\x05\x05\x05\x05\x05'
            # before the cipher text modification (hack thing)
            print("decrypted:")
            print(cipher.decrypt(encrypted_list[i]))
            decrypted = cipher.decrypt(encrypted_list[i])
            
        else:
            decrypted = cipher.decrypt(encrypted_list[i])

        if i != 0:
            plain_text = bitwise_xor_bytes(encrypted_list[i - 1], decrypted) + plain_text
        else:
            plain_text = bitwise_xor_bytes(iv, decrypted) + plain_text
    
    plain_text = unpad(plain_text, BLOCKSIZE, style='pkcs7')
    if bytes(";admin=true;", "utf-8") in plain_text:
        return True
    else:
        return False


def hack_verify(encrypted):
    print("len(block_cipher_text): ")
    print(len(block_cipher_text))
    encrypted_string = block_cipher_text[0] + block_cipher_text[1]
    print("before attack")
    print(block_cipher_text[len(block_cipher_text) -1])
    bye_78 = bitwise_and_bytes(block_cipher_text[2], b"\x00\x0f\x0f\x0f\x0f\x0f\x00\x0f\x0f\x0f\x0f\x00\x0f\x0f\x0f\x0f")
    replace_0 = bitwise_and_bytes(bye_78, b"\x3B\x0f\x0f\x0f\x0f\x0f\x3D\x0f\x0f\x0f\x0f\x3B\x0f\x0f\x0f\x0f")
    encrypted_string += replace_0
    i = 3
    while (i < len(block_cipher_text)):
        encrypted_string += block_cipher_text[i]
        i += 1
    print("after attack")
    print(encrypted_string[-16:])
    print("len(encrypted_string): ")
    print(len(encrypted_string))
    return encrypted_string


# ecb_mode("mustang.bmp")
# cbc_mode("mustang.bmp")
# submit("8admin7true8") #8admin7true8



"""userid=456;userdata=
8admin7true8; 000000000
session-id=31337 000000"""



print_bytes_all()
print("\n\n")

print("------------------")
print(submit("abcg"))
print("------------------")
print(verify(submit("abcdefg")))
# print(verify(hack_verify(submit("8admin7true8"))))

