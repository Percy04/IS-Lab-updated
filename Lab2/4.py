# Encrypt
# the
# message
# "Classified
# Text"
# using
# Triple
# DES
# "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF".
# with
# Then
# thekey
# decryptthe
# ciphertext to verify the original message.
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
import base64
key = bytes.fromhex('1234567890abcdef0123456789abcdef1234567890abcdef')
print(len('401b7cfe0ee5b7f4bca2275834b2bc146b8bc7f7c8d7d671'))
#01245abfd7841fedb140a254dbc784adecb4175eace62a4c
# key=get_random_bytes(24)
print(key)
text1 = b'Classified Text'
print(key.hex())
padded_text = pad(text1, DES3.block_size)

des = DES3.new(key, DES3.MODE_CBC)

encrypted_text = des.encrypt(padded_text)
enc_text=base64.b64encode(encrypted_text).decode('ascii')
print("Encrypted text: ", enc_text)

des_decrypt = DES3.new(key, DES3.MODE_CBC,iv=des.iv)
decrypted_padded = des_decrypt.decrypt(encrypted_text)


decrypted_text = unpad(decrypted_padded, DES3.block_size)

print("Decrypted text:", decrypted_text.decode())
