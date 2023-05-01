print("here")
print(chr(ord(b"\x0f") ^ ord("6") ^ ord ("7")))
#print(b"\x0f" ^ b"\x0f")


def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")
def bitwise_and_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") & int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

print(bitwise_and_bytes(b"\x0f", b"\x00"))