from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Configuration

## changing this to false will cause an invalid signature if public key is still being read (False)
GENERATE_PRIVATE_KEY = True

## changing this to false will result in a differnet final signature, probably due to time differences
DERIVE_PUBLIC_KEY_FROM_PRIVATE_KEY = True

## use keys/message I created myself
PRIVATE_KEY_FILE = "ryankey.pem"
PUBLIC_KEY_FILE = "ryankey.pub"
MESSAGE = b"Ryan likes Pokemon"

## get the private key
if GENERATE_PRIVATE_KEY:
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
else:
    # Load private key from pem file
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

## define the signature using the private key
signature = private_key.sign(
    MESSAGE,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("~" * 30, "Attributes of Private Key Object:", private_key.__dict__, sep='\n')

## get the public key
if DERIVE_PUBLIC_KEY_FROM_PRIVATE_KEY:
    # Getting public key from private key
    public_key = private_key.public_key()
else:
    # Load public key from file
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

## observe the public key object
print("~" * 30, "Attributes of Public Key Object:", public_key.__dict__, "~" * 30, sep='\n')

## now verify, if there's an issue, it will occur here
public_key.verify(
    signature,
    MESSAGE,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("Final Signature")
print(signature)
