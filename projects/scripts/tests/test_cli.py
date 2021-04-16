import sys

from mixbag.scripts.cli import PyScript, main


def test_pyscript_success(mocker):
    sys_exit = mocker.patch("sys.exit")
    pyscript = PyScript()
    sys.argv = ["pyscript", "success_script"]
    pyscript.run()
    assert sys_exit.called
    assert sys_exit.called_once_with(0)


def test_pyscript_failure(mocker):
    sys_exit = mocker.patch("sys.exit")
    pyscript = PyScript()
    sys.argv = ["pyscript", "failure_script"]
    pyscript.run()
    assert sys_exit.called
    assert sys_exit.called_once_with(1)


def test_main(mocker):
    run = mocker.patch("mixbag.scripts.cli.PyScript.run")
    main()
    assert run.called
