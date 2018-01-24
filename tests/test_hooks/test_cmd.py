# -*- coding: utf-8 -*-

import subprocess

import pytest
from mock import patch

from awsscripter.common.exceptions import InvalidHookArgumentTypeError
from awsscripter.hooks.cmd import Cmd


class TestCmd(object):
    def setup_method(self, test_method):
        self.cmd = Cmd()

    def test_run_with_non_str_argument(self):
        self.cmd.argument = None
        with pytest.raises(InvalidHookArgumentTypeError):
            self.cmd.run()

    @patch('awsscripter.hooks.cmd.subprocess.check_call')
    def test_run_with_str_argument(self, mock_call):
        self.cmd.argument = u"echo hello"
        self.cmd.run()
        mock_call.assert_called_once_with(u"echo hello", shell=True)

    @patch('awsscripter.hooks.cmd.subprocess.check_call')
    def test_run_with_erroring_command(self, mock_call):
        mock_call.side_effect = subprocess.CalledProcessError(1, "echo")
        self.cmd.argument = u"echo hello"
        with pytest.raises(subprocess.CalledProcessError):
            self.cmd.run()
