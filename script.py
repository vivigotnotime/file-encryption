import sys
from twofish import Twofish
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # Twofish block size (128 bits)

# Generate a strong key using PBKDF2
def derive_key(password: bytes, salt: bytes, key_length=32, iterations=100000) -> bytes:
    return PBKDF2(password, salt, dkLen=key_length, count=iterations)

# Encrypt a file using Twofish (block-wise encryption)
def encrypt_file(input_file, output_file, password):
    salt = get_random_bytes(16)  # Random salt for PBKDF2
    key = derive_key(password, salt)
    cipher = Twofish(key)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padded_data = pad(plaintext, BLOCK_SIZE)

    # Encrypt in 16-byte blocks
    ciphertext = b"".join(cipher.encrypt(padded_data[i:i+BLOCK_SIZE]) for i in range(0, len(padded_data), BLOCK_SIZE))

    # Save salt + ciphertext
    with open(output_file, 'wb') as f:
        f.write(salt + ciphertext)

# Decrypt a file using Twofish (block-wise decryption)
def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        salt = f.read(16)  # Extract salt
        ciphertext = f.read()  # Remaining is ciphertext

    key = derive_key(password, salt)
    cipher = Twofish(key)

    # Decrypt in 16-byte blocks
    decrypted_padded_data = b"".join(cipher.decrypt(ciphertext[i:i+BLOCK_SIZE]) for i in range(0, len(ciphertext), BLOCK_SIZE))

    decrypted_data = unpad(decrypted_padded_data, BLOCK_SIZE)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# CLI Mode using sys.argv
def cli_mode():
    if len(sys.argv) < 5:
        print("Usage: python script.py <encrypt/decrypt> <input_file> <output_file> <password>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    password = sys.argv[4].encode()

    if mode == 'encrypt':
        encrypt_file(input_file, output_file, password)
        print(f"File encrypted and saved as {output_file}")
    elif mode == 'decrypt':
        decrypt_file(input_file, output_file, password)
        print(f"File decrypted and saved as {output_file}")
    else:
        print("Invalid mode. Please choose 'encrypt' or 'decrypt'.")
        sys.exit(1)

# Interactive Mode
def interactive_mode():
    print("Welcome to the interactive mode!")
    mode = input("Do you want to encrypt or decrypt a file? (encrypt/decrypt): ").strip().lower()
    if mode not in ['encrypt', 'decrypt']:
        print("Invalid mode. Please choose 'encrypt' or 'decrypt'.")
        return

    input_file = input("Enter the path to the input file: ").strip()
    output_file = input("Enter the path to the output file: ").strip()
    password = input("Enter your password: ").strip()

    if mode == 'encrypt':
        encrypt_file(input_file, output_file, password.encode())
        print(f"File encrypted and saved as {output_file}")
    elif mode == 'decrypt':
        decrypt_file(input_file, output_file, password.encode())
        print(f"File decrypted and saved as {output_file}")

# Main program entry point
if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()
