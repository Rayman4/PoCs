import base64
from Crypto.Cipher import DES3
import codecs

def decrypt_text(cipher_text, encryption_private_key):
    """
    Decrypt text that was encrypted using Triple DES

    Args:
        cipher_text (str): Base64 encoded encrypted text
        encryption_private_key (str): The encryption key used for encryption

    Returns:
        str: Decrypted plaintext
    """
    # Check for empty input
    if not cipher_text:
        return cipher_text

    # Extract the key and IV same way as in C# code
    key = encryption_private_key[0:16].encode('ascii')
    iv = encryption_private_key[8:16].encode('ascii')

    # Decode the base64 string to get the encrypted bytes
    encrypted_data = base64.b64decode(cipher_text)

    # Create the cipher object with the same key and IV
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Remove padding (PKCS7 padding is commonly used)
    pad_len = decrypted_data[-1]
    if pad_len < len(decrypted_data):
        decrypted_data = decrypted_data[:-pad_len]

    # Convert bytes to string
    try:
        return decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        # If UTF-8 decoding fails, try with another encoding or return as hex
        return decrypted_data.hex()

# Example usage
if __name__ == "__main__":
    encrypted_text = input("Enter the encrypted text (Base64): ")
    key = input("Enter the encryption key: ")

    try:
        decrypted = decrypt_text(encrypted_text, key)
        print(f"Decrypted text: {decrypted}")
    except Exception as e:
        print(f"Decryption failed: {e}")
