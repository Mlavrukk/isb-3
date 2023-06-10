import argparse

from symmetric import generate_symmetric_key, encrypt_symmetric, decrypt_symmetric
from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from system_functions import load_settings, save_asymmetric_keys, save_symmetric_key, load_private_key, load_symmetric_key, read_text, write_text

SETTINGS_FILE = 'settings.json'

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
    if settings:
        if args.generation:
            symmetric_key = generate_symmetric_key()
            private_key, public_key = generate_asymmetric_keys()
            save_asymmetric_keys(private_key, public_key,
                                 settings['secret_key'], settings['public_key'])
            cipher_symmetric_key = encrypt_asymmetric(
                public_key, symmetric_key)
            save_symmetric_key(cipher_symmetric_key, settings['symmetric_key'])
        elif args.encryption:
            private_key = load_private_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decrypt_asymmetric(private_key, cipher_key)
            text = read_text(settings['initial_file'])
            cipher_text = encrypt_symmetric(symmetric_key, text)
            write_text(cipher_text, settings['encrypted_file'])
        else:
            private_key = load_private_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decrypt_asymmetric(private_key, cipher_key)
            cipher_text = read_text(settings['encrypted_file'])
            text = decrypt_symmetric(symmetric_key, cipher_text)
            write_text(text, settings['decrypted_file'])