import secrets
import codecs
import hashlib
import ecdsa

# -----------------------------------------------------------------------------------------------------------------------
# The first step is creating a private key. use secrets library in python for creating a random 256-bit number

private_key_intiger = secrets.randbits(256)
private_key_hex_format = hex(private_key_intiger)
# This is my final private key that i use for creating public key
private_key = private_key_hex_format[2:]
print(private_key)


# -----------------------------------------------------------------------------------------------------------------------
''' Next step -> creating public key from the private key 
bitcoin use Elliptic Curve for creating public key from the private key'''

'''There is 2 types of public key named uncompressed and compressed 
A compressed key is just a way of storing a public key in fewer bytes (33 instead of 65). 
There are no compatibility or security issues because they are precisely the same keys, just stored in a different way'''


# This is the function for creating uncompressed public key
def create_uncompressed_public_key_from_private(private_key):
    # decode private key from hex to byte
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(
        private_key_bytes, curve=ecdsa.SECP256k1).verifying_key  # signing public key with your private key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Add bitcoin byte
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    return public_key


# This is the function for creating compressed public key
def create_compressed_public_key_from_private(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(
        private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    # Get X from the key (first half)
    key_string = key_hex.decode('utf-8')
    half_len = len(key_hex) // 2
    key_half = key_hex[:half_len]
    # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
    last_byte = int(key_string[-1], 16)
    bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
    public_key = bitcoin_byte + key_half
    return public_key


print((create_uncompressed_public_key_from_private(private_key)))
print((create_compressed_public_key_from_private(private_key)))


# -----------------------------------------------------------------------------------------------------------------------
# Now that we have a public key so we can create an address from that public key
