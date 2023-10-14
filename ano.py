from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# Generate a private/public key pair
private_key = ec.generate_private_key(ec.SECP384R1())
public_key = private_key.public_key()

# Get the message from user input
message = input("Enter the message to encrypt: ").encode()

# Encrypt the message using Fernet symmetric encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(message)

# Sign the encrypted message using ECDSA
signature = private_key.sign(
    cipher_text,
    ec.ECDSA(hashes.SHA256())
)

# Encode the key, cipher_text, and signature as base64 for storage/transmission
encoded_key = base64.urlsafe_b64encode(key).decode()
encoded_cipher_text = base64.urlsafe_b64encode(cipher_text).decode()
encoded_signature = base64.urlsafe_b64encode(encode_dss_signature(*signature)).decode()

# Print the encoded key, cipher_text, and signature
print("Encoded key:", encoded_key)
print("Encoded cipher text:", encoded_cipher_text)
print("Encoded signature:", encoded_signature)

# Verify the signature for authenticity
decoded_signature = base64.urlsafe_b64decode(encoded_signature)
decoded_cipher_text = base64.urlsafe_b64decode(encoded_cipher_text)
try:
    public_key.verify(
        decoded_signature,
        decoded_cipher_text,
        ec.ECDSA(hashes.SHA256())
    )
    print("Digital signature verified.")
except:
    print("Invalid digital signature.")
