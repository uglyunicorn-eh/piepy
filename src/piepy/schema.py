from typing import Annotated, Any, cast
from pydantic import TypeAdapter, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

from piepy.core import EnvelopeContext, EnvelopeData


class EnvelopeField:
    """Pydantic annotation that adapts field behavior based on envelope context."""

    def __init__(self, inner_type: type):
        self.inner_type = inner_type

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        inner_type = self.inner_type
        inner_adapter = TypeAdapter[Any](inner_type)
        envelope_adapter = TypeAdapter[EnvelopeData](EnvelopeData)

        def validate(value: Any, info) -> Any:
            ctx = cast(EnvelopeContext, (info.context or {}).get("~piepy")) if info else None

            if ctx is None:
                return inner_adapter.validate_python(value)

            if "open" in ctx and "seal" in ctx:
                env = envelope_adapter.validate_python(value)
                opened = ctx.get("open")(inner_type, env)
                return ctx.get("seal")(inner_type, opened)

            if "open" in ctx:
                env = envelope_adapter.validate_python(value)
                return ctx.get("open")(inner_type, env)

            if "seal" in ctx:
                validated = inner_adapter.validate_python(value)
                return ctx.get("seal")(inner_type, validated)

            return envelope_adapter.validate_python(value)

        return core_schema.with_info_plain_validator_function(validate)


class Envelope:
    """Generic envelope marker: Envelope[Identity] marks a field as sealable."""

    def __class_getitem__(cls, inner_type: type):
        return Annotated[Any, EnvelopeField(inner_type)]
