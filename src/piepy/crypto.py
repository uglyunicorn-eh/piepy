from typing import Any, TypedDict

from pydantic import BaseModel
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyInterface

from piepy.core import EnvelopeContext, EnvelopeData
from piepy.utils import base64url_to_bytes, bytes_to_base64url


def create_cipher_suite():
    """
    Creates a new cipher suite.

    Returns:
        A new cipher suite.
    """
    return CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def seal_envelope(schema: BaseModel, data: Any, public_key: KEMKey) -> EnvelopeData:
    """
    Seals data into an envelope.

    Args:
        schema: The schema to validate the data against.
        data: The data to seal.
        public_key: The public key to use for the envelope.

    Returns:
        An envelope containing the sealed data.

    Raises:
        ValidationError: If the data does not match the schema.
    """
    buffer = schema.model_dump_json(data).encode("utf-8")

    suite = create_cipher_suite()
    enc, sender = suite.create_sender_context(public_key)
    ct = sender.seal(buffer)

    return {
        "ct": bytes_to_base64url(ct),
        "enc": bytes_to_base64url(enc),
    }


def open_envelope(schema: BaseModel, envelope: EnvelopeData, private_key: KEMKey) -> Any:
    """
    Opens an envelope and validates the data against the schema.

    Args:
        schema: The schema to validate the data against.
        envelope: The envelope to open.
        private_key: The private key to use for the envelope.

    Returns:
        The data from the envelope.

    Raises:
        ValidationError: If the data does not match the schema.
    """
    ct = base64url_to_bytes(envelope["ct"])
    enc = base64url_to_bytes(envelope["enc"])

    suite = create_cipher_suite()
    recipient = suite.create_recipient_context(enc, private_key)
    buffer = recipient.open(ct)

    return schema.model_validate_json(buffer.decode("utf-8"))


class InOpts(TypedDict):
    private_key: KEMKeyInterface


class OutOpts(TypedDict):
    public_key: KEMKeyInterface


class InOutOpts(InOpts, OutOpts):
    pass


class NoOpts(TypedDict):
    pass


def envelope_context(opts: InOutOpts | InOpts | OutOpts | NoOpts | None = None) -> EnvelopeContext:
    def context():
        if opts is None:
            return None

        if "private_key" in opts and "public_key" in opts:
            return {
                "open": lambda schema, envelope: open_envelope(schema, envelope, opts["private_key"]),
                "seal": lambda schema, data: seal_envelope(schema, data, opts["public_key"]),
            }

        if "private_key" in opts:
            return {
                "open": lambda schema, envelope: open_envelope(schema, envelope, opts["private_key"]),
            }

        if "public_key" in opts:
            return {
                "seal": lambda schema, data: seal_envelope(schema, data, opts["public_key"]),
            }

        return None

    return {
        "~piepy": context(),
    }
