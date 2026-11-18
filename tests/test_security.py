import pytest
from argon2.exceptions import InvalidHashError

from security import hash_password, verify_password


def test_correct_password_is_accepted():
    password = "A fictional password for this test"
    stored_hash = hash_password(password)

    assert verify_password(password, stored_hash) is True


def test_wrong_password_is_rejected():
    stored_hash = hash_password("The original test password")

    assert verify_password("A different password", stored_hash) is False


def test_same_password_produces_different_hashes():
    password = "The same fictional password"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash
    assert verify_password(password, first_hash) is True
    assert verify_password(password, second_hash) is True


def test_malformed_stored_hash_raises_an_error():
    with pytest.raises(InvalidHashError):
        verify_password("A fictional password", "not-an-argon2-hash")
