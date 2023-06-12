import argparse

from symmetric import generate_symmetric_key, encrypt_symmetric, decrypt_symmetric
from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from system_functions import load_settings, save_asymmetric_keys, save_symmetric_key, load_private_key, load_symmetric_key, read_text, write_text

SETTINGS_FILE = 'settings.json'

def generate_and_save_keys(settings):
    """
    Generates and saves keys using the provided settings.

    Args:
        settings: A dictionary containing the settings for key generation.
            Must contain the following keys:
                - 'secret_key': The file path to save the private key.
                - 'public_key': The file path to save the public key.
                - 'symmetric_key': The file path to save the encrypted symmetric key.

    """
    symmetric_key = generate_symmetric_key()
    private_key, public_key = generate_asymmetric_keys()
    save_asymmetric_keys(private_key, public_key,
    settings['secret_key'], settings['public_key'])
    cipher_symmetric_key = encrypt_asymmetric( public_key, symmetric_key)
    save_symmetric_key(cipher_symmetric_key, settings['symmetric_key'])

def encrypt_file(settings):
    """
    Encrypts a file using the provided settings.

    Args:
        settings: A dictionary containing the settings for file encryption.
            Must contain the following keys:
                - 'secret_key': The file path to load the private key.
                - 'public_key': The file path to load the public key.
                - 'symmetric_key': The file path to load the encrypted symmetric key.
                - 'initial_file': The file path to the file to be encrypted.
                - 'encrypted_file': The file path to save the encrypted file.

    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = decrypt_asymmetric(private_key, cipher_key)
    text = read_text(settings['initial_file'])
    cipher_text = encrypt_symmetric(symmetric_key, text)
    write_text(cipher_text, settings['encrypted_file'])

def decrypt_file(settings):
    """
    Decrypts a file using the provided settings.

    Args:
        settings : A dictionary containing the settings for file decryption.
            Must contain the following keys:
                - 'secret_key': The file path to load the private key.
                - 'symmetric_key': The file path to load the encrypted symmetric key.
                - 'encrypted_file': The file path to the encrypted file.
                - 'decrypted_file': The file path to save the decrypted file.

    """
    private_key = load_private_key(settings['secret_key'])
    cipher_key = load_symmetric_key(settings['symmetric_key'])
    symmetric_key = decrypt_asymmetric(private_key, cipher_key)
    cipher_text = read_text(settings['encrypted_file'])
    text = decrypt_symmetric(symmetric_key, cipher_text)
    write_text(text, settings['decrypted_file'])

        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=SETTINGS_FILE, type=str, help='Позволяет использовать собственный json-файл с указанием путей'
                        '(Введите путь к файлу)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true',
                       help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true',
                       help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true',
                       help='Запускает режим дешифрования')
    args = parser.parse_args()
    settings = load_settings(args.settings)
    if args.generation:
        generate_and_save_keys(settings)
    if args.encryption:
        encrypt_file(settings)
    if args.decryption:
        decrypt_file(settings)


