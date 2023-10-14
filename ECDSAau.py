from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import os

# Generate a new EC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Get the corresponding public key
public_key = private_key.public_key()

# Serialize the public key to send it to the device
serialized_public_key = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

# Sign a message using the private key
message = b"Hello, world!"
signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

# Verify the signature using the public key
try:
    public_key.verify(
        signature,
        message,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    print("Signature is valid.")
except InvalidSignature:
    print("Signature is invalid.")

