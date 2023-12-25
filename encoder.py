from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt(data, key):
    """
    Function to encrypt data using AES with a 512-bit key.

    :param data: Binary data to be encrypted.
    :type data: bytes
    :param key: Key for AES encryption. Must be 64 bytes long.
    :type key: bytes
    :return: Encrypted data.
    :rtype: bytes
    """
    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be bytes")

    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Encryption key must be 32 bytes long")
    
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    with open("encryption_key.bin", "wb") as key_file:
        key_file.write(key)

    return encrypted_data

def decrypt(encrypted_data, key, iv):
    """
    Function to decrypt data using AES with a 512-bit key.

    :param encrypted_data: Binary data to be decrypted.
    :type encrypted_data: bytes
    :param key: Key for AES encryption. Must be 64 bytes long.
    :type key: bytes
    :param iv: Initialization vector (IV) for AES decryption.
    :type iv: bytes
    :return: Decrypted data.
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Example usage:
file_path = r"C:\Users\max-BP\Desktop\sss.txt"
with open(file_path, 'rb') as file:
    data_to_encrypt = pad(file.read(), AES.block_size)  # Ensure data is padded

encryption_key = get_random_bytes(32)
encrypted_data = encrypt(data_to_encrypt, encryption_key)

with open("encrypted_file.bin", "wb") as encrypted_file:
    encrypted_file.write(encrypted_data)

# Save the key used for file encryption to a separate file
with open("file_encryption_key.bin", "wb") as key_file:
    key_file.write(encryption_key)

# Example of decrypting the encryption key file
with open("encrypted_file.bin", "rb") as encrypted_file:
    encrypted_data_to_decrypt = encrypted_file.read()

with open("file_encryption_key.bin", "rb") as key_file:
    key_for_decryption = key_file.read()

# Decrypt the data
decrypted_data = decrypt(encrypted_data_to_decrypt, key_for_decryption, get_random_bytes(AES.block_size))
