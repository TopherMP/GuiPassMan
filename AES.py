from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_CBC)
textoPlano = b"ola"

encode = base64.b64encode(textoPlano).decode("utf-8")

cipherText = cipher.encrypt(pad(textoPlano,AES.block_size))

decipher = AES.new(key, AES.MODE_CBC, cipher.iv)
decrypted = unpad(decipher.decrypt(cipherText),AES.block_size)
decode = decrypted.decode()

print(encode)

print(cipherText)

print(decrypted)

print(decode)