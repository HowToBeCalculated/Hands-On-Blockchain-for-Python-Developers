from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

message = b'Ryan hates Pokemon'
## checkout 'verify_message.py' to see how a signature usually looks like, obviously this is fake
signature = b'Fake Signature'

#load in our public key
with open("ryankey.pub", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend())

print("~" * 30, "Attributes of Public Key Object:", public_key.__dict__, "~" * 30, sep='\n')

## verification will fail as signature is not as expected
public_key.verify(
 signature,
 message,
 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256())
