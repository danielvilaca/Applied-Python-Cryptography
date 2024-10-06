def encrypt(plaintext, shift_key):

    ciphertext = ""

    for char in plaintext:

        if char.isupper():

            char_index = ord(char) - ord("A")

            char_shifted = (char_index + shift_key) % 26 + ord("A")

            char_encrypted = chr(char_shifted)

            ciphertext += char_encrypted

        elif char.islower():

            char_index = ord(char) - ord("a")

            char_shifted = (char_index + shift_key) % 26 + ord("a")

            char_encrypted = chr(char_shifted)

            ciphertext += char_encrypted

        else:

            ciphertext += char

    return ciphertext

def decrypt(ciphertext, shift_key):

    decrpyted_plaintext = ""

    for char in ciphertext:

        if char.isupper():

            char_index = ord(char) - ord("A")

            char_unshifted = (char_index - shift_key) % 26 + ord("A")

            char_decrypted = chr(char_unshifted)

            decrpyted_plaintext += char_decrypted

        elif char.islower():

            char_index = ord(char) - ord("a")

            char_unshifted = (char_index - shift_key) % 26 + ord("a")

            char_decrypted = chr(char_unshifted)

            decrpyted_plaintext += char_decrypted

        else:

            decrpyted_plaintext += char

    return decrpyted_plaintext

plaintext = input("Enter the text to encrypt: ")
shift_key = int(input("Enter the shift key: "))
ciphertext = encrypt(plaintext, shift_key)
decrypted_plaintext = decrypt(ciphertext, shift_key)

print("Plaintext: " + plaintext)
print("Character shift: " + str(shift_key))
print("Encrypted plaintext: " + ciphertext)
print("Decrypted plaintext: " + decrypted_plaintext)
