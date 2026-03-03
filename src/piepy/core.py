from collections.abc import Callable
from typing import Any, TypedDict

from pydantic import BaseModel


class EnvelopeData(TypedDict):
    '''
    An envelope containing the sealed data.

    Args:
        ct: The ciphertext.
        enc: The encryption key.
    '''
    ct: str
    enc: str


class CipherContext(TypedDict):
    '''
    A context for sealing data.

    Args:
        seal: A function that seals data into an envelope.
    '''
    seal: Callable[[BaseModel, Any], EnvelopeData]


class DecipherContext(TypedDict):
    '''
    A context for deciphering data.

    Args:
        open: A function that opens an envelope and returns the data.
    '''
    open: Callable[[BaseModel, EnvelopeData], Any]


class RetranslateContext(TypedDict):
    '''
    A context for retranslating data.

    Args:
        open: A function that opens an envelope and returns the data.
        seal: A function that seals data into an envelope.
    '''
    open: Callable[[BaseModel, EnvelopeData], Any]
    seal: Callable[[BaseModel, Any], EnvelopeData]


type EnvelopeContext = CipherContext | DecipherContext | RetranslateContext
