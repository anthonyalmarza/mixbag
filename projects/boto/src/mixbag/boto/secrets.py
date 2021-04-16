import json

import boto3


class Secrets:
    """
    Usage:
        secrets = Secrets()
        secret = secrets.get_secret(secret_arn)
        secret_from_json = secrets.get_secret(json_secret_arn, key="password")
    """

    _secretsmanager = None

    def __init__(self):
        pass

    @property
    def secretsmanager(self):
        """
        :return: boto secrets manager client
        """
        if self._secretsmanager is None:
            self._secretsmanager = boto3.client("secretsmanager")
        return self._secretsmanager

    def get_secret(self, secret_id: str, key: str = None):
        """
        :param secret_id: ARN of the secret
        :param key: Optional key to the json object
        :return: str
        """
        secret_string = self.secretsmanager.get_secret_value(
            SecretId=secret_id
        )["SecretString"]
        if key:
            return json.loads(secret_string)[key]
        return secret_string


secrets = Secrets()
