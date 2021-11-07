import secrets
# First step is creating a private key i use secrets library in python for creating a random 256 bit number

private_key_intiger = secrets.randbits(256)
private_key_hex_format = hex(private_key_intiger)
private_key = private_key_hex_format[2:] # This is my final private key that i use for creating public key
print(private_key)

# Next step -> creating public key from private key
