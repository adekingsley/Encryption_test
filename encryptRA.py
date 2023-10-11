import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from base64 import urlsafe_b64encode
import base64
import random
import string


# Generate a random password
passw = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
print(len(passw))
password = urlsafe_b64encode(passw.encode())

# Create an instance of the AES cipher using the password
key = password[:32]
cipher = Cipher(algorithms.AES(key), modes.CTR(os.urandom(16)), backend=default_backend())

# Encrypt the money transfer amount using AES encryption
amount = b'1000'
nonce = os.urandom(16)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(amount) + encryptor.finalize()

# Generate a new ECDSA key pair with the secp256r1 curve
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Sign the encrypted message using the private key
data_to_sign = b"".join([nonce, ciphertext])
signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

# Serialize the private key to PEM format and save it to a file
private_key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
with open('private_key.pem', 'wb') as f:
    f.write(private_key_pem)

# Serialize the public key to PEM format and save it to a file
public_key_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

# Print the original message, encrypted message, signature, and password to verify they were generated correctly
print(f"Amount: {amount}")
print(f"Encrypted message: {ciphertext}")
print(f"Nonce: {nonce}")
print(f"Signature: {base64.b64encode(signature).decode('utf-8')}")
print(f"Password: {password.decode('utf-8')}")
