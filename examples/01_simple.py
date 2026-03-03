from pydantic import BaseModel

from piepy import Envelope, create_cipher_suite, envelope_context


class Identity(BaseModel):
    name: str
    email: str


class Payload(BaseModel):
    identity: Envelope[Identity]


suite = create_cipher_suite()
key_pair = suite.kem.derive_key_pair(b"your-secret-key-material")

# Seal: validate with plain data + public key → field becomes encrypted envelope
ctx_seal = envelope_context({"public_key": key_pair.public_key})
sealed = Payload.model_validate(
    {"identity": {"name": "Alice", "email": "alice@example.com"}},
    context=ctx_seal,
)
print("sealed:", sealed)
# sealed.identity is now {"ct": "...", "enc": "..."}

# Open: validate with envelope + private key → field becomes decrypted Identity
ctx_open = envelope_context({"private_key": key_pair.private_key})
opened = Payload.model_validate(sealed.model_dump(), context=ctx_open)
print("opened:", opened)

assert opened.identity == Identity(name="Alice", email="alice@example.com")
