from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode

BLOCKSIZE = AES.block_size
key = get_random_bytes(BLOCKSIZE)
iv = get_random_bytes(BLOCKSIZE)

############ helper functions ##################
# From https://techoverflow.net/2020/09/27/how-to-fix-python3-typeerror-unsupported-operand-types-for-bytes-and-bytes/
def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")
def bitwise_and_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") & int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")


############ encrypt it ################
padded_plain = pad(bytes("Hello World", "utf-8") , AES.block_size, style='pkcs7')
aes_obj = AES.new(key, AES.MODE_ECB)

current_block = bitwise_xor_bytes(padded_plain, iv)
cipher_text = aes_obj.encrypt(current_block)

########## decrypt it ##################
#cipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(bitwise_xor_bytes(iv, aes_obj.decrypt(cipher_text)), BLOCKSIZE, style='pkcs7')

print(decrypted)

list = [1, 2, 3, 4]
for i in range(len(list) - 1, 0, -1):
    print("hello", list[i])

print(bitwise_and_bytes(b"\x0b\x0e\x0f", b"\x0f\x0f\x0f"))