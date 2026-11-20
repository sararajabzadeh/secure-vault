from pydantic import BaseModel, ConfigDict, Field, SecretStr


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
    )

    username: str = Field(
        min_length=3,
        max_length=32,
        pattern=r"^[a-z0-9_]+$",
    )

    password: SecretStr = Field(
        min_length=15,
        max_length=128,
    )


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
    )

    username: str = Field(
        min_length=3,
        max_length=32,
        pattern=r"^[a-z0-9_]+$",
    )

    password: SecretStr = Field(
        min_length=1,
        max_length=128,
    )
