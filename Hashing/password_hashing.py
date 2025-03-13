import hashlib

def sha256_hash_password(example_password, input_password):

    example_sha256_hash = hashlib.sha256(example_password).hexdigest()
    input_sha256_hash = hashlib.sha256(input_password).hexdigest()

    print ("Example Password: ", example_password.decode("ASCII"))
    print ("Example SHA256 Hash: ", example_sha256_hash)
    print ("Input Password: ", input_password.decode("ASCII"))
    print ("Input SHA256 Hash: ", input_sha256_hash)

    if (example_sha256_hash == input_sha256_hash):
        print ("Passwords Match!")
    else:
        print ("Passwords Do Not Match!")

example_password = "password123".encode("ASCII")
input_password = input("Enter a Password: ").encode("ASCII")

sha256_hash_password(example_password, input_password)
