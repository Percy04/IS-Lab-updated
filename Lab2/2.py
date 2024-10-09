# Encrypt the message "Sensitive Information" using AES-128 with the following key:
# "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to verify the
# original message.
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import base64

key =bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

message="Sensitive Information"
data=message.encode()
cipher=AES.new(key,AES.MODE_CBC)

ctext=cipher.encrypt(pad(data,AES.block_size))
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=cipher.iv)

# Decrypt the data
plaintext = unpad(cipher_decrypt.decrypt(ctext), AES.block_size)
print("Encryptes message: ",base64.b64encode(ctext).decode('ascii'))
print(plaintext)
