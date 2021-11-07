import secrets
import codecs
import hashlib
import ecdsa
from ecdsa.ecdsa import Public_key

# -----------------------------------------------------------------------------------------------------------------------
# The first step is creating a private key. use secrets library in python for creating a random 256-bit number

private_key_intiger = secrets.randbits(256)
private_key_hex_format = hex(private_key_intiger)
# This is my final private key that i use for creating public key
private_key = private_key_hex_format[2:]


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
    # Get X from the key for creating compressed key(first half)
    key_string = key_hex.decode('utf-8')
    half_len = len(key_hex) // 2
    key_half = key_hex[:half_len]
    # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
    last_byte = int(key_string[-1], 16)
    bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
    public_key = bitcoin_byte + key_half
    return public_key


# -----------------------------------------------------------------------------------------------------------------------
# Now that we have a public key so we can create an address from that public key
compressed_public_key = create_compressed_public_key_from_private(private_key)

'''1 : Apply SHA-256 hash function on the public key (you should decode hex before SHA-256) .
2 : Apply RIPEMD-160 hash function on the result of step one (SHA-256 of public key).
3 : Add the version byte prefix to step two, which is used to define different address formats — 6f is the version byte (0x6f for TestNet Network).
4 : Apply/Implement two times SHA-256 hash function on step 3 (SHA-256(SHA-256(ripemd-160WithVersionByte))).
5 : Get the first 4 bytes from step 4, which is the output of the second SHA-256 function(CheckSum).
6 : Add checksum to the end of the RIPEMD-160 hash with version byte .'''


def create_address_from_public_key(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    public_key_sha_256 = hashlib.new('sha256', public_key_bytes).digest()
    public_key_ripemd160 = hashlib.new(
        'ripemd160', public_key_sha_256).digest()
    public_key_ripemd160_hex = codecs.encode(public_key_ripemd160, 'hex')
    network_byte = b'6f'
    network_bitcoin_public_key = network_byte + public_key_ripemd160_hex
    network_bitcoin_public_key_bytes = codecs.decode(
        network_bitcoin_public_key, 'hex')
    sha256_first_time = hashlib.new(
        'sha256', network_bitcoin_public_key_bytes).digest()
    sha256_second_time = hashlib.new(
        'sha256', sha256_first_time).digest()
    sha256_second_time_hex = codecs.encode(
        sha256_second_time, 'hex')
    checksum = sha256_second_time_hex[:8]
    add_checksum_to_network_bitcoin_public_key = network_bitcoin_public_key + checksum
    address_hex = add_checksum_to_network_bitcoin_public_key.decode('utf-8')
    final_address = base58(address_hex)
    return final_address


# Function for converting to base58


def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def create_address():
    private_key = hex(secrets.randbits(256))[2:]
    public_key = create_compressed_public_key_from_private(private_key)
    address = create_address_from_public_key(public_key)
    print("Private key => ", private_key)
    print("Public key => ", public_key)
    print("Address => ", address)
    print("=============================================================================")


print("Sender Address")
create_address()
print("Receiver Address")
create_address()
