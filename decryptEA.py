from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from base64 import urlsafe_b64decode, urlsafe_b64encode

# Load the provided public key
with open("public_key.pem", "rb") as key_file:
    public_key = load_pem_public_key(key_file.read())

# Load the encrypted message and signature
encrypted_message = b'gAAAAABkL-mEgN-f1Sl6yPq9MjQI2vP-23ijscdEsfCmUzqOJbJTZ0seGttAMeLLNs58xZY5ENRCRVZEIYQqWJ340Yfl29235A=='
signature = b'MEUCIHjZEgmm16uBpDcC4O30W0RLcRDHDqguBrQohd+FSlGZAiEAuCEaCGQjR9mKKUBkpvSWmEjENUEUX4s7fA7+lUHDKwE='
# Get the password used for encryption from user input
password = input("Enter the password used for encryption: ").encode()

# Derive a 32-byte url-safe base64-encoded Fernet key from the password
salt = b'\xcb\x90&0\xfa\x92c\x8eL\xaeK\xb4\xe9\n\r'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = urlsafe_b64encode(kdf.derive(password))

# Verify the digital signature
message_hash = hashes.Hash(hashes.SHA256())
message_hash.update(encrypted_message)
digest = message_hash.finalize()

try:
    public_key.verify(signature, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    print("Digital signature verified.")
except:
    print("Invalid digital signature.")

# Create an instance of the Fernet cipher using the key
cipher = Fernet(key)

# Decrypt the encrypted message using the Fernet cipher
decrypted_message = cipher.decrypt(urlsafe_b64decode(encrypted_message)).decode()

# Print the decrypted message
print(f"Decrypted message: {decrypted_message}")
