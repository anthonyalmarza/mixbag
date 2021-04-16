import pytest

from mixbag.utils.module_loading import import_string


def test_incorrect_path_module_only():
    with pytest.raises(ImportError):
        import_string("tests")


def test_incorrect_path_no_such_attr():
    with pytest.raises(ImportError):
        import_string("tests.fixture_module.does_not_exist")


def test_success():
    assert import_string("tests.fixture_module.exists") == "foobar"
