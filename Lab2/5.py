# Encrypt
# the
# message
# "Top
# Secret
# Data"
# using
# AES-192
# with
# the
# key
# "FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the encryption
# process (key expansion, initial round, main rounds, final round).
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import base64

key =bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")

message="Top Secret Data"
data=message.encode()
cipher=AES.new(key,AES.MODE_CBC)

ctext=cipher.encrypt(pad(data,AES.block_size))
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=cipher.iv)

# Decrypt the data
plaintext = unpad(cipher_decrypt.decrypt(ctext), AES.block_size)
print("Encryptes message: ",base64.b64encode(ctext).decode('ascii'))
print(plaintext)
