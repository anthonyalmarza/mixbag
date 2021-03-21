from unittest import mock

from mixbag.secrets import secrets


def test_get_secret(mocker):
    boto_client = mocker.patch("boto3.client")
    secret_arn_value = "fake"
    secret = secrets.get_secret(secret_arn_value)
    assert boto_client.called
    assert (
        secret
        == boto_client("secretsmanager").get_secret_value(
            SecretId=secret_arn_value
        )["SecretString"]
    )


def test_get_secret_with_key(mocker):
    boto_client = mocker.patch("mixbag.secrets.Secrets.secretsmanager")
    password = "super-secret"
    boto_client.get_secret_value = mock.MagicMock(
        return_value={"SecretString": '{"password": "%s"}' % password}
    )
    secret_arn_value = "fake"
    secret = secrets.get_secret(secret_arn_value, key="password")
    assert boto_client.get_secret_value.called
    assert secret == password
