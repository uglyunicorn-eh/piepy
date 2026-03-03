from typing import Any, TypedDict, cast

from pydantic import BaseModel
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyInterface

from piepy.core import EnvelopeContext, EnvelopeData
from piepy.utils import base64url_to_bytes, bytes_to_base64url


def create_cipher_suite() -> CipherSuite:
    """
    Creates a new cipher suite.

    Returns:
        A new cipher suite.
    """
    return CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def seal_envelope(schema: type[BaseModel], data: Any, public_key: KEMKeyInterface) -> EnvelopeData:
    """
    Seals data into an envelope.

    Args:
        schema: The schema to validate the data against.
        data: Raw data (e.g. dict) to validate against the schema and seal.
        public_key: The public key to use for the envelope.

    Returns:
        An envelope containing the sealed data.

    Raises:
        ValidationError: If the data does not match the schema.
    """
    validated = schema.model_validate(data)
    buffer = validated.model_dump_json().encode("utf-8")

    suite = create_cipher_suite()
    enc, sender = suite.create_sender_context(public_key)
    ct = sender.seal(buffer)

    return {
        "ct": bytes_to_base64url(ct),
        "enc": bytes_to_base64url(enc),
    }


def open_envelope(schema: type[BaseModel], envelope: EnvelopeData, private_key: KEMKeyInterface) -> Any:
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


class PydanticContext(TypedDict):
    piepy: EnvelopeContext | None


def envelope_context(
    opts: InOutOpts | InOpts | OutOpts | NoOpts | None = None,
) -> PydanticContext:
    def context() -> EnvelopeContext | None:
        if opts is None:
            return None

        if "private_key" in opts and "public_key" in opts:
            inout = cast(InOutOpts, opts)
            return cast(
                EnvelopeContext,
                {
                    "open": lambda schema, envelope: open_envelope(schema, envelope, inout["private_key"]),
                    "seal": lambda schema, data: seal_envelope(schema, data, inout["public_key"]),
                },
            )

        if "private_key" in opts:
            in_opts = cast(InOpts, opts)
            return cast(
                EnvelopeContext,
                {
                    "open": lambda schema, envelope: open_envelope(schema, envelope, in_opts["private_key"]),
                },
            )

        if "public_key" in opts:
            out_opts = cast(OutOpts, opts)
            return cast(
                EnvelopeContext,
                {
                    "seal": lambda schema, data: seal_envelope(schema, data, out_opts["public_key"]),
                },
            )

        return None

    return {
        "piepy": context(),
    }
