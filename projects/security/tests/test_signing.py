from datetime import timedelta

import pytest

from mixbag.security.signing import BadToken, Signer


@pytest.fixture()
def signer():
    return Signer(key="fake")


@pytest.mark.unit
class TestSigner:
    def test_basic_signer_signature(self, signer: Signer):
        value = "foo"
        token = signer.sign(value)
        assert len(token.split(signer.sep)) == 3
        assert token != value
        assert (
            value
            == signer.validate(token=token, max_age=100)
            == signer.validate(token=token)
            == signer.validate(token=token, max_age=timedelta(seconds=100))
        )

    def test_validation_token_structure(self, signer: Signer):
        with pytest.raises(BadToken) as exc:
            signer.validate(token="nosep")
        assert str(exc.value) == "Separator not found in token"

    def test_validation_token_parts(self, signer: Signer):
        with pytest.raises(BadToken) as exc:
            signer.validate(token=signer.sep.join(["has", "sep"]))
        assert str(exc.value) == "Invalid token structure"

    def test_validation_timeout(self, signer: Signer, mocker):
        with pytest.raises(BadToken) as exc:
            signer.validate(
                signer.sign("value"),
                timestamp_validator=mocker.Mock(return_value=False),
            )
        assert str(exc.value) == "Token has expired"

    def test_validation_signature(self, signer: Signer, mocker):
        with pytest.raises(BadToken) as exc:
            signer.validate(
                signer.sign("value"),
                signature_validator=mocker.Mock(return_value=False),
            )
        assert str(exc.value) == "Signatures do not match"

    def test_bad_separator(self):
        with pytest.raises(ValueError) as exc:
            Signer(key="fake", sep="a")
        assert str(exc.value).startswith("Unsafe Signer separator")
