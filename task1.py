def caesar_cipher_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def main():
    print("Caesar Cipher Program")
    choice = input("Type 'encrypt' to encrypt or 'decrypt' to decrypt: ").strip().lower()

    if choice not in ['encrypt', 'decrypt']:
        print("Invalid choice. Please select 'encrypt' or 'decrypt'.")
        return

    message = input("Enter your message: ")
    try:
        shift = int(input("Enter the shift value (an integer): "))
    except ValueError:
        print("Invalid shift value. Please enter an integer.")
        return

    if choice == 'encrypt':
        encrypted = caesar_cipher_encrypt(message, shift)
        print("Encrypted message:", encrypted)
    else:
        decrypted = caesar_cipher_decrypt(message, shift)
        print("Decrypted message:", decrypted)

if __name__ == "__main__":
    main()
