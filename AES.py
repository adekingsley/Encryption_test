from cryptography.fernet import Fernet
import random
import string
import base64

# Generate a random password
password = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# Create an instance of the Fernet cipher using the password
cipher = Fernet(base64.urlsafe_b64encode(password.encode('utf-8')))

# Encrypt the money transfer amount using AES encryption
amount = '1000'
encrypted_amount = cipher.encrypt(amount.encode())

# Decrypt the encrypted message using the same password
decrypted_amount = cipher.decrypt(encrypted_amount).decode()

# Print the original message and decrypted message to verify they match
print(password)
print(f"Original message: {amount}")
print(f"Decrypted message: {decrypted_amount}")
