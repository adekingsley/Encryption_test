import hmac
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# Generate a random key to use for encryption and decryption
key = secrets.token_bytes(32)

# Use the SHA-256 hash algorithm to generate the MAC
mac_algorithm = hashes.SHA256()

# Compute the MAC for the ciphertext
ciphertext = b'This is a secret message'
mac = hmac.HMAC(key, mac_algorithm, backend=default_backend())
mac.update(ciphertext)
mac_digest = mac.finalize()
print(mac_digest)

# Encrypt the MAC using the key
nonce = os.urandom(16)
mac_encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).encryptor()
mac_encrypted = mac_encryptor.update(mac_digest) + mac_encryptor.finalize()
print(mac_encrypted)

# Decrypt the MAC using the key
mac_decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).decryptor()
mac_decrypted = mac_decryptor.update(mac_encrypted) + mac_decryptor.finalize()
print(mac_decrypted)

# Verify that the decrypted MAC matches the original MAC
assert mac_digest == mac_decrypted
