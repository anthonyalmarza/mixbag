import json
import logging
import sys
import traceback
from typing import Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class CustomResourceEventHandler:
    """
    CustomResourceEventHandler is a base class designed to expose a clean
    interface to accomodate the AWS Custom Resource lifecycle.

    Usage:
        # in a lambda handler.py
        from mixbag.aws.custom_resources import CustomResourceEventHandler

        class MyCustomResource(CustomResourceEventHandler):
            def on_create(self, event, context):
                ...
            def on_update(self, event, context):
                ...
            def on_delete(self, event, context):
                ...

        handler = MyCustomResource()
    """

    def __init__(self, *, physical_id: Optional[str] = None):
        """
        :param physical_id: str
        """
        self._physical_id = physical_id

    def __call__(self, event, context):
        """
        :param event:
        :param context:
        :return:
        """
        logger.info("Starting request.")
        request_type = event["RequestType"]
        if request_type == "Create":
            return self.handle_event(self.on_create, event, context)
        if request_type == "Update":
            return self.handle_event(self.on_update, event, context)
        if request_type == "Delete":
            return self.handle_event(self.on_delete, event, context)
        raise ValueError("Invalid request type: %s" % request_type)

    @property
    def physical_id(self) -> str:
        """
        Return the physical id of the resource.
        :return: string
        """
        if self._physical_id is None:
            self._physical_id = str(
                hash(f"{__file__}::{self.__class__.__name__}")
            )
        return self._physical_id

    def on_create(self, event, context):
        """
        Override this method to manage the `create` stage of the resource
        lifecycle.

        :param event:
        :param context:
        :return: JSON Serializerable Object
        """
        raise NotImplementedError()

    def on_update(self, event, context):
        """
        Override this method to manage the `update` stage of the resource
        lifecycle.

        :param event:
        :param context:
        :return: JSON Serializerable Object
        """
        raise NotImplementedError()

    def on_delete(self, event, context):
        """
        Override this method to manage the `delete` stage of the resource
        lifecycle.

        :param event:
        :param context:
        :return: JSON Serializerable Object
        """
        raise NotImplementedError()

    def handle_event(self, method, event, context):
        """

        :param method:
        :param event:
        :param context:
        :return:
        """
        try:
            logger.info("Handling lifecyle event: %s", event["RequestType"])
            logger.info(json.dumps(self.clean_event(event)))
            data = method(event, context)
            response = self.success(event, data=data)
        except Exception as exc:  # pylint: disable=broad-except
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback_string = traceback.format_exception(
                exc_type, exc_value, exc_traceback
            )
            err_msg = json.dumps(
                {
                    "errorType": exc_type.__name__,
                    "errorMessage": str(exc_value),
                    "stackTrace": traceback_string,
                }
            )
            logger.error(err_msg)
            response = self.failure(event, str(exc))
        return response

    def clean_event(self, event):  # pylint: disable=no-self-use
        """
        Override this method to clean the event before it gets logged.

        :param event:
        :return: JSON Serializerable Object
        """
        return event

    def get_response(self, status, event, reason=None, data=None):
        """
        Return the expected response structure for custom resources.

        :param status: string SUCCESS | FAILED
        :param event:
        :param reason:
        :param data:
        :return: Dict[str, str]
        """
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-responses.html
        return {
            "Status": status,
            "Reason": reason,
            "PhysicalResourceId": self.physical_id,
            "RequestId": event["RequestId"],
            "StackId": event["StackId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Data": data,
        }

    def success(self, event, data=None):
        """
        Convinience method to structure successful responses.

        :param event:
        :param data: output from the on_create, on_update, on_delete methods
        :return: get_response output
        """
        return self.get_response("SUCCESS", event, data=data)

    def failure(self, event, reason: str):
        """
        Convinience method to structure failed responses.

        :param event:
        :param reason: string
        :return: get_response output
        """
        return self.get_response("FAILED", event, reason=reason)
