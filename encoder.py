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

    # Сохранение ключа для шифрования в безопасном формате
    with open("encryption_key.bin", "wb") as key_file:
        key_file.write(key)

    return encrypted_data


def decrypt(encrypted_data, key, iv):
    """
    Функция для дешифратор данных на 512 битах с использованием AES.

    :param data: Бинарные данные для шифрования.
    :type data: bytes
    :param key: Ключ для AES шифрования. Должен быть длиной 64 байта.
    :type key: bytes
    :return: Зашифрованные данные.
    :rtype: bytes
    """
            # Создание объекта AES для дешифрования с использованием предоставленного ключа и вектора инициализации (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
        # Расшифровка данных с использованием AES в режиме CBC
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        # Возврат расшифрованных данных
    return decrypted_data



# Пример использования:
file_path = "C:/путь/к/файлу"
with open(file_path, 'rb') as file:
    data_to_encrypt = file.read()

encryption_key = get_random_bytes(64)
encrypted_data = encrypt(data_to_encrypt, encryption_key)


# Генерация случайного вектора инициализации (IV) длиной, соответствующей размеру блока шифрования AES
iv = get_random_bytes(AES.block_size)
# Расшифровка зашифрованных данных, используя предоставленный ключ и сгенерированный вектор инициализации
decrypted_data = decrypt(encrypted_data, encryption_key, iv)

