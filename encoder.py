from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt(data, key):
    """
    Функция для шифрования данных на 512 битах с использованием AES.

    :param data: Бинарные данные для шифрования.
    :type data: bytes
    :param key: Ключ для AES шифрования. Должен быть длиной 64 байта.
    :type key: bytes
    :return: Зашифрованные данные.
    :rtype: bytes
    """

    if not isinstance(data, bytes):
        raise TypeError("Данные для шифрования должны быть байтами")

    if not isinstance(key, bytes):
        raise TypeError("Ключ для шифрования должен быть байтами")

    if len(data) % AES.block_size != 0:
        raise ValueError("Размер данных для шифрования должен быть кратен размеру блока шифрования AES (16 байтов)")

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    # Сохранить ключ для шифрования
    with open("encryption_key.bin", "wb") as file:
        file.write(key)

    return encrypted_data
    



# Пример использования:
# укажіте файл для шыврования 
file_path = "C:/файл"
with open(file_path, 'rb') as file:
    data_to_encrypt = file.read()

encryption_key = get_random_bytes(64)  # Генерация случайного ключа длиной 64 байта (512 бит)
encrypted_data = encrypt(data_to_encrypt, encryption_key)


