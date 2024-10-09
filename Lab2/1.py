# Encrypt the message "Confidential Data" using DES with the following key: "A1B2C3D4".
# Then decrypt the ciphertext to verify the original message.
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad
import base64
key = b'A1B2C3D4'   
# key = bytes.fromhex('A1B2C3D4')
text1 = b'Confidential Data!'

padded_text = pad(text1, DES.block_size)

des = DES.new(key, DES.MODE_ECB)

encrypted_text = des.encrypt(padded_text)
enc_text=base64.b64encode(encrypted_text).decode('ascii')
print("Encrypted text: ", enc_text)

des_decrypt = DES.new(key, DES.MODE_ECB)
decrypted_padded = des_decrypt.decrypt(encrypted_text)


decrypted_text = unpad(decrypted_padded, DES.block_size)

print("Decrypted text:", decrypted_text.decode())
