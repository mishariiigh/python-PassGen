import string

def caesar_encrypt(message: str, key: int) -> str:
    """Encrypts a message using the Caesar cipher."""
    shift = key % 26
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase

    # Translation tables for lower and upper case
    cipher_lower = str.maketrans(lowercase, lowercase[shift:] + lowercase[:shift])
    cipher_upper = str.maketrans(uppercase, uppercase[shift:] + uppercase[:shift])

    # Apply both translations
    encrypted_message = message.translate(cipher_lower).translate(cipher_upper)
    return encrypted_message


def caesar_decrypt(encrypted_message: str, key: int) -> str:
    """Decrypts a message encrypted with the Caesar cipher."""
    shift = 26 - (key % 26)
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase

    cipher_lower = str.maketrans(lowercase, lowercase[shift:] + lowercase[:shift])
    cipher_upper = str.maketrans(uppercase, uppercase[shift:] + uppercase[:shift])

    message = encrypted_message.translate(cipher_lower).translate(cipher_upper)
    return message


if __name__ == "__main__":
    message = "Ping!!!, Mishari, Ping!!!"
    key = 3

    encrypted_message = caesar_encrypt(message, key)
    print(f"Encrypted message: {encrypted_message}")

    decrypted_message = caesar_decrypt(encrypted_message, key)
    print(f"Decrypted message: {decrypted_message}")
