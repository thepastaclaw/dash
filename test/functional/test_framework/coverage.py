#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for doing coverage analysis on the RPC interface.

Provides a way to track which RPC commands are exercised during
testing.
"""

import os
import shutil
import tempfile
import unittest

from .authproxy import AuthServiceProxy

REFERENCE_FILENAME = 'rpc_interface.txt'


class AuthServiceProxyWrapper():
    """
    An object that wraps AuthServiceProxy to record specific RPC calls.

    """
    def __init__(self, auth_service_proxy_instance: AuthServiceProxy, rpc_url: str, coverage_logfile: str=None):
        """
        Kwargs:
            auth_service_proxy_instance: the instance being wrapped.
            rpc_url: url of the RPC instance being wrapped
            coverage_logfile: if specified, write each service_name
                out to a file when called.

        """
        self.auth_service_proxy_instance = auth_service_proxy_instance
        self.rpc_url = rpc_url
        self.coverage_logfile = coverage_logfile

    def __getattr__(self, name):
        return_val = getattr(self.auth_service_proxy_instance, name)
        if not isinstance(return_val, type(self.auth_service_proxy_instance)):
            # If proxy getattr returned an unwrapped value, do the same here.
            return return_val
        return AuthServiceProxyWrapper(return_val, self.rpc_url, self.coverage_logfile)

    def __call__(self, *args, **kwargs):
        """
        Delegates to AuthServiceProxy, then writes the particular RPC method
        called to a file.

        """
        return_val = self.auth_service_proxy_instance.__call__(*args, **kwargs)
        self._log_call()
        return return_val

    def _log_call(self):
        rpc_method = self.auth_service_proxy_instance._service_name

        if self.coverage_logfile:
            # The coverage directory is shared across all test processes and may
            # be removed (e.g. cleanup of a sibling tmpdir) before this append
            # runs. Recreate it so coverage logging keeps working instead of
            # crashing the test with FileNotFoundError.
            os.makedirs(os.path.dirname(self.coverage_logfile), exist_ok=True)
            with open(self.coverage_logfile, 'a+', encoding='utf8') as f:
                f.write("%s\n" % rpc_method)

    def __truediv__(self, relative_uri):
        return AuthServiceProxyWrapper(self.auth_service_proxy_instance / relative_uri,
                                       self.rpc_url,
                                       self.coverage_logfile)

    def get_request(self, *args, **kwargs):
        self._log_call()
        return self.auth_service_proxy_instance.get_request(*args, **kwargs)

def get_filename(dirname, n_node):
    """
    Get a filename unique to the test process ID and node.

    This file will contain a list of RPC commands covered.
    """
    pid = str(os.getpid())
    return os.path.join(
        dirname, "coverage.pid%s.node%s.txt" % (pid, str(n_node)))


def write_all_rpc_commands(dirname: str, node: AuthServiceProxy) -> bool:
    """
    Write out a list of all RPC functions available in `dash-cli` for
    coverage comparison. This will only happen once per coverage
    directory.

    Args:
        dirname: temporary test dir
        node: client

    Returns:
        if the RPC interface file was written.

    """
    filename = os.path.join(dirname, REFERENCE_FILENAME)

    if os.path.isfile(filename):
        return False

    help_output = node.help().split('\n')
    commands = set()

    for line in help_output:
        line = line.strip()

        # Ignore blanks and headers
        if line and not line.startswith('='):
            commands.add("%s\n" % line.split()[0])

    # The coverage directory is shared across processes and may have been
    # removed before this reference file is written. Recreate it so the
    # write succeeds and the post-run coverage report has the reference it
    # needs.
    os.makedirs(dirname, exist_ok=True)
    with open(filename, 'w', encoding='utf8') as f:
        f.writelines(list(commands))

    return True


class _FakeProxy:
    """Minimal stand-in for AuthServiceProxy used by the unit tests below."""
    def __init__(self, service_name="getblockcount", help_text=""):
        self._service_name = service_name
        self._help_text = help_text

    def help(self):
        return self._help_text


class CoverageDirectoryRecreationTest(unittest.TestCase):
    """Regression tests for issue #7273.

    The shared coverage directory can disappear mid-run (e.g. another test
    process clears its tmpdir). Coverage writes must recreate it instead of
    crashing with FileNotFoundError.
    """

    def setUp(self):
        self.dirname = tempfile.mkdtemp(prefix="coverage_test_")
        self.addCleanup(shutil.rmtree, self.dirname, ignore_errors=True)

    def test_log_call_recreates_missing_directory(self):
        logfile = get_filename(self.dirname, n_node=0)
        wrapper = AuthServiceProxyWrapper(_FakeProxy("getblockcount"),
                                          rpc_url="http://test",
                                          coverage_logfile=logfile)

        # Simulate the shared coverage dir vanishing before a logged call.
        shutil.rmtree(self.dirname)
        self.assertFalse(os.path.exists(self.dirname))

        wrapper._log_call()

        self.assertTrue(os.path.isfile(logfile))
        with open(logfile, 'r', encoding='utf8') as f:
            self.assertEqual(f.read(), "getblockcount\n")

    def test_write_all_rpc_commands_recreates_missing_directory(self):
        proxy = _FakeProxy(help_text="== Blockchain ==\ngetblockcount\ngetbestblockhash\n")

        # Simulate the shared coverage dir vanishing before the reference write.
        shutil.rmtree(self.dirname)
        self.assertFalse(os.path.exists(self.dirname))

        self.assertTrue(write_all_rpc_commands(self.dirname, proxy))

        ref_file = os.path.join(self.dirname, REFERENCE_FILENAME)
        self.assertTrue(os.path.isfile(ref_file))
        with open(ref_file, 'r', encoding='utf8') as f:
            written = set(line.strip() for line in f.readlines())
        self.assertEqual(written, {"getblockcount", "getbestblockhash"})
