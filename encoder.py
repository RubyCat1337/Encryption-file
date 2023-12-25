from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt(data, key):
    """
    Функція для шифрування даних за допомогою AES з ключем 512 біт.

    :param data: Бінарні дані для шифрування.
    :type data: bytes
    :param key: Ключ для шифрування AES. Має бути довжиною 64 байти.
    :type key: bytes
    :return: Зашифровані дані.
    :rtype: bytes
    """
    if not isinstance(data, bytes):
        raise TypeError("Дані для шифрування повинні бути байтами")

    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Ключ шифрування повинен мати довжину 32 байти")

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    with open("encryption_key.bin", "wb") as key_file:
        key_file.write(key)

    return encrypted_data

def decrypt(encrypted_data, key, iv):
    """
    Функція для розшифрування даних за допомогою AES з ключем 512 біт.

    :param encrypted_data: Бінарні дані для розшифрування.
    :type encrypted_data: bytes
    :param key: Ключ для шифрування AES. Має бути довжиною 64 байти.
    :type key: bytes
    :param iv: Вектор ініціалізації (IV) для розшифрування AES.
    :type iv: bytes
    :return: Розшифровані дані.
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Приклад використання:
file_path = r"C:\Users\max-BP\Desktop\sss.txt"
with open(file_path, 'rb') as file:
    data_to_encrypt = pad(file.read(), AES.block_size)  # Забезпечте відступ для даних

encryption_key = get_random_bytes(32)
encrypted_data = encrypt(data_to_encrypt, encryption_key)

with open("encrypted_file.bin", "wb") as encrypted_file:
    encrypted_file.write(encrypted_data)

# Збереження ключа, використаного для шифрування файлу, у окремому файлі
with open("file_encryption_key.bin", "wb") as key_file:
    key_file.write(encryption_key)

# Приклад розшифрування файлу з ключем шифрування
with open("encrypted_file.bin", "rb") as encrypted_file:
    encrypted_data_to_decrypt = encrypted_file.read()

with open("file_encryption_key.bin", "rb") as key_file:
    key_for_decryption = key_file.read()

# Розшифрування даних
decrypted_data = decrypt(encrypted_data_to_decrypt, key_for_decryption, get_random_bytes(AES.block_size))

with open("decrypted_file.txt", "wb") as decrypted_file:
    decrypted_file.write(decrypted_data)
