import os
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64
import string


# Generate a random password using a cryptographically secure random number generator
passw = secrets.token_urlsafe(32)
password = passw.encode()

# Derive a 256-bit AES key using PBKDF2 with a random salt and 100,000 iterations
salt = secrets.token_bytes(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Create an instance of the AES cipher using the derived key and a random IV
iv = secrets.token_bytes(16)
cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())

# Encrypt the money transfer amount using AES encryption
amount = b'1000'
encryptor = cipher.encryptor()
ciphertext = encryptor.update(amount) + encryptor.finalize()

# Generate a new ECDSA key pair with the secp256r1 curve
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Sign the encrypted message using the private key and the SHA-256 hash algorithm
data_to_sign = b"".join([iv, ciphertext])
signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

# Serialize the private key to PEM format and save it to a file encrypted with a passphrase
passphrase = "mysecurepassphrase"
encryption_algorithm = hashes.SHA256()
encryption_salt = secrets.token_bytes(16)
encryption_iterations = 524288
kdf = Scrypt(
    salt=encryption_salt,
    length=32,
    n=encryption_iterations,
    r=8,
    p=1,
    backend=default_backend()
)
key = kdf.derive(passphrase.encode())
cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
encryptor = cipher.encryptor()
private_key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
encrypted_private_key_pem = encryptor.update(private_key_pem) + encryptor.finalize()
with open('private_key.pem', 'wb') as f:
    f.write(encrypted_private_key_pem)

# Serialize the public key to PEM format and save it to a file
public_key_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

# Verify the signature using the public key
public_key = private_key.public_key()
data_to_verify = b"".join([iv, ciphertext])
try:
    public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
    print("Signature is valid")
except: # InvalidSignature:
    print("Signature is not valid")

# Generate a random key to use for message authentication code (MAC)
mac_key = secrets.token_bytes(32)

# Use the SHA-256 hash algorithm to generate the MAC
mac_algorithm = hashes.SHA256()

# Compute the MAC for the ciphertext
mac = hmac.HMAC(mac_key, mac_algorithm, backend=default_backend())
mac.update(ciphertext)
mac_digest = mac.finalize()

# Encrypt the MAC using the password
nonce = os.urandom(16)
mac_encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).encryptor()
mac_encrypted = mac_encryptor.update(mac_digest) + mac_encryptor.finalize()

# Decrypt the MAC using the password
mac_decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend()).decryptor()
mac_decrypted = mac_decryptor.update(mac_encrypted) + mac_decryptor.finalize()

# Verify that the decrypted MAC matches the original MAC
assert mac_digest == mac_decrypted

# Serialize the private key to PEM format and encrypt it using a password before saving it to a file
passwo = secrets.token_urlsafe(32)
password2 = passwo.encode()
password_bytes = password2
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password2))
iv = os.urandom(16)
encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
private_key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
private_key_encrypted = encryptor.update(private_key_pem) + encryptor.finalize()

# Save the encrypted private key to a file
with open('private_key.enc', 'wb') as f:
    f.write(b'Salted__' + salt + private_key_encrypted)

# Deserialize the private key from the encrypted PEM format using the password
with open('private_key.enc', 'rb') as f:
    header = f.read(8)
if header != b'Salted__':
    raise ValueError('Invalid private key file format')
salt = f.read(8)
encrypted_data = f.read()
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
iv = encrypted_data[:16]
decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
private_key = serialization.load_pem_private_key(decrypted_data, password=None, backend=default_backend())

# Serialize the public key to PEM format and save it to a file
public_key_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
with open('public_key.pem', 'wb') as f:
    f.write(public_key_pem)

# Print the original message, encrypted message, signature, MAC, and password to verify they were generated correctly
print(f"Amount: {amount}")
print(f"Encrypted message: {ciphertext}")
print(f"Signature: {base64.b64encode(signature).decode('utf-8')}")
print(f"MAC: {base64.b64encode(mac_encrypted).decode('utf-8')}")
print(f"Password: {password.decode('utf-8')}")