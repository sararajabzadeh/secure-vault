import pytest
from pydantic import ValidationError

from schemas import RegistrationRequest


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("abc", "x" * 15),
        ("a" * 32, "x" * 128),
        ("sara_27", " A very long password "),
    ],
)
def test_registration_accepts_valid_input(
    username: str,
    password: str,
) -> None:
    request = RegistrationRequest.model_validate(
        {"username": username, "password": password}
    )

    assert request.username == username
    assert request.password.get_secret_value() == password
    assert password not in repr(request)
    assert password not in request.model_dump_json()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("username", "ab"),
        ("username", "a" * 33),
        ("username", "Sara"),
        ("username", "sara rajab"),
        ("username", "sara!"),
        ("username", "sara\n"),
        ("username", 123),
        ("password", ""),
        ("password", "x" * 14),
        ("password", "x" * 129),
        ("password", None),
    ],
)
def test_registration_rejects_invalid_input(
    field: str,
    value: object,
) -> None:
    payload: dict[str, object] = {
        "username": "sara_27",
        "password": "a-password-used-only-for-testing",
    }
    payload[field] = value

    with pytest.raises(ValidationError) as exc_info:
        RegistrationRequest.model_validate(payload)

    assert any(error["loc"] == (field,) for error in exc_info.value.errors())


def test_registration_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError) as exc_info:
        RegistrationRequest.model_validate(
            {
                "username": "sara_27",
                "password": "a-password-used-only-for-testing",
                "role": "admin",
            }
        )

    assert any(
        error["loc"] == ("role",) and error["type"] == "extra_forbidden"
        for error in exc_info.value.errors()
    )


def test_formatted_validation_error_hides_password() -> None:
    password = "short-secret"

    with pytest.raises(ValidationError) as exc_info:
        RegistrationRequest.model_validate(
            {"username": "sara_27", "password": password}
        )

    assert password not in str(exc_info.value)
