from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(plaintext)  
    return cipher.iv + ciphertext  # Including IV for decryption later

def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def main():
    block_size = 16
    plaintext1 = b"IS703 Information System Security!!"  # Original plaintext
    plaintext2 = b"IS703 Information System Security"  # Modified plaintext

    padded_plaintext1 = pad(plaintext1, block_size)
    padded_plaintext2 = pad(plaintext2, block_size)

    key = get_random_bytes(16)  # AES key (128-bit)
    des_key = get_random_bytes(8)  # DES key (64-bit)

    aes_ciphertext1 = encrypt_aes(padded_plaintext1, key)
    aes_ciphertext2 = encrypt_aes(padded_plaintext2, key)

    des_ciphertext1 = encrypt_des(padded_plaintext1, des_key)
    des_ciphertext2 = encrypt_des(padded_plaintext2, des_key)

    print("AES Ciphertext 1:", aes_ciphertext1.hex())
    print("AES Ciphertext 2:", aes_ciphertext2.hex())

    print("DES Ciphertext 1:", des_ciphertext1.hex())
    print("DES Ciphertext 2:", des_ciphertext2.hex())

    # Check and print differences
    aes_diff = bytes(a ^ b for a, b in zip(aes_ciphertext1, aes_ciphertext2))
    des_diff = bytes(a ^ b for a, b in zip(des_ciphertext1, des_ciphertext2))

    print("Difference in AES Ciphertexts:", aes_diff.hex())
    print("Difference in DES Ciphertexts:", des_diff.hex())

if __name__ == "__main__":  # Corrected main block
    main()
