import pytest
from typing import Dict, Any

from mixbag.custom_resources import CustomResourceEventHandler


class DummyHandler(CustomResourceEventHandler):

    updated: bool = False
    created: bool = False
    deleted: bool = False

    def on_update(self, event, context):
        self.updated = not self.updated

    def on_create(self, event, context):
        self.created = not self.created
        return event["PhysicalResourceId"]

    def on_delete(self, event, context):
        self.deleted = not self.deleted


CONTEXT: Dict[str, Any] = {}


def generate_event(request_type: str):
    return {
        "ResourceProperties": {},
        "PhysicalResourceId": "id",
        "RequestType": request_type,
        "RequestId": "request_id",
        "StackId": "stack_id",
        "LogicalResourceId": "logical_resource_id",
    }


def test_create_event():
    dummy = DummyHandler()
    assert not dummy.created
    dummy(generate_event("Create"), CONTEXT)
    assert dummy.created


def test_update_event():
    dummy = DummyHandler()
    assert not dummy.updated
    dummy(generate_event("Update"), CONTEXT)
    assert dummy.updated


def test_delete_event():
    dummy = DummyHandler()
    assert not dummy.deleted
    dummy(generate_event("Delete"), CONTEXT)
    assert dummy.deleted


def test_interface():
    interface = CustomResourceEventHandler()
    with pytest.raises(NotImplementedError):
        interface.on_create({}, CONTEXT)

    with pytest.raises(NotImplementedError):
        interface.on_update({}, CONTEXT)

    with pytest.raises(NotImplementedError):
        interface.on_delete({}, CONTEXT)

    with pytest.raises(ValueError):
        interface({"RequestType": "Wrong"}, CONTEXT)
