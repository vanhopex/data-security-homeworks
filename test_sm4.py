from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'0123456789abcdef'
plaintext = b'0123456789abcdef'

cipher = Cipher(algorithms.SM4(key), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext)

print(ciphertext.hex())