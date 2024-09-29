#from Crypto.Cipher import AES
#from Crypto.Random import get_random_bytes
#from Crypto.Util.Padding import pad, unpad
#import base64
#
#key = get_random_bytes(32)
#cipher = AES.new(key, AES.MODE_CBC)
#textoPlano = b"ola"
#
#encode = base64.b64encode(textoPlano).decode("utf-8")
#
#cipherText = cipher.encrypt(pad(textoPlano,AES.block_size))
#
#decipher = AES.new(key, AES.MODE_CBC, cipher.iv)
#decrypted = unpad(decipher.decrypt(cipherText),AES.block_size)
#decode = decrypted.decode()
#
#print(encode)
#
#print(cipherText)
#
#print(decrypted)
#
#print(decode)

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generar clave AES simétrica
def generate_aes_key():
    return get_random_bytes(32)  # Clave AES de 256 bits

# Cifrar las contraseñas con AES
def encrypt_with_aes(aes_key, data):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode('utf-8'))
    return (cipher_aes.nonce, ciphertext, tag)

# Desencriptar las contraseñas con AES
def decrypt_with_aes(aes_key, nonce, ciphertext, tag):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Cifrar la clave AES con RSA (clave pública)
def encrypt_aes_key_with_rsa(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

# Desencriptar la clave AES con RSA (clave privada)
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

# Ejemplo de uso
# Generar claves RSA
rsa_key = RSA.generate(2048)
private_rsa_key = rsa_key
public_rsa_key = rsa_key.publickey()

# Cifrado de las contraseñas
clave_aes = generate_aes_key()
nonce, encrypted_data, tag = encrypt_with_aes(clave_aes, "MiSuperContraseña123")

# Cifrar la clave AES con la clave pública RSA
encrypted_aes_key = encrypt_aes_key_with_rsa(clave_aes, public_rsa_key)

# Desencriptar la clave AES con la clave privada RSA
decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_rsa_key)

# Desencriptar los datos con AES
decrypted_data = decrypt_with_aes(decrypted_aes_key, nonce, encrypted_data, tag)

print(encrypted_aes_key)
print("\n")
print(decrypted_aes_key)

print("Contraseña desencriptada:", decrypted_data)
