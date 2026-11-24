#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load_verify_module():
    spec = importlib.util.spec_from_file_location("verify_binaries_empty", Path(__file__).with_name("verify.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EmptyHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load_verify_module()

    def test_published_all_filtered_fails_and_ordinary_binary_passes(self):
        verify = self.verify
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = b"offline binary fixture"
            digest = hashlib.sha256(payload).hexdigest()
            selected_name = "bitcoin-99.0-x86_64-linux.tar.gz"
            args = argparse.Namespace(
                version="99.0-x86_64-linux",
                require_all_hosts=False,
                cleanup=False,
                json=True,
            )

            def run(manifest):
                downloads = []

                def fetch(_hosts, _remote, filename, _require_all):
                    Path(filename).write_text(manifest if filename == verify.SUMS_FILENAME else "signature")
                    return verify.ReturnCode.SUCCESS

                def download(_remote, filename):
                    downloads.append(filename)
                    Path(filename).write_bytes(payload)
                    return True, ""

                old_cwd = Path.cwd()
                output = io.StringIO()
                try:
                    with (
                        patch.object(verify.tempfile, "gettempdir", return_value=temp_dir),
                        patch.object(verify, "get_files_from_hosts_and_compare", side_effect=fetch),
                        patch.object(
                            verify,
                            "verify_shasums_signature",
                            return_value=(verify.ReturnCode.SUCCESS, [], [], [], []),
                        ),
                        patch.object(verify, "download_with_wget", side_effect=download),
                        contextlib.redirect_stdout(output),
                    ):
                        status = verify.verify_published_handler(args)
                finally:
                    os.chdir(old_cwd)
                return status, downloads, output.getvalue()

            filtered = ""
            for fragment in ("-unsigned", "-debug", "-codesignatures"):
                with self.subTest(fragment=fragment):
                    filtered = f"{digest}  bitcoin-99.0-x86_64-linux{fragment}.tar.gz\n"
                    status, downloads, output = run(filtered)
                    self.assertEqual(status, verify.ReturnCode.NO_BINARIES_MATCH)
                    self.assertEqual(downloads, [])
                    self.assertEqual(output, "")

            args.cleanup = True
            status, _, _ = run(filtered)
            self.assertEqual(status, verify.ReturnCode.NO_BINARIES_MATCH)
            self.assertFalse((Path(temp_dir) / f"bitcoin_verify_binaries.{args.version}").exists())
            args.cleanup = False

            valid = f"{digest}  {selected_name}\n"
            status, downloads, output = run(valid)
            self.assertEqual(status, verify.ReturnCode.SUCCESS)
            self.assertEqual(downloads, [selected_name])
            self.assertIn(selected_name, output)

    def test_local_all_missing_fails_but_partial_presence_succeeds(self):
        verify = self.verify
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            present = base / "present.tar.gz"
            missing = base / "missing.tar.gz"
            present.write_bytes(b"legitimate local binary")
            digest = hashlib.sha256(present.read_bytes()).hexdigest()
            sums = base / verify.SUMS_FILENAME
            sums.write_text(f"{digest}  {present.name}\n{digest}  {missing.name}\n")
            args = argparse.Namespace(
                sums_sig_file=str(base / verify.SIGNATUREFILENAME),
                sums_file=str(sums),
                binary=[],
                json=True,
            )
            with patch.object(
                verify,
                "verify_shasums_signature",
                return_value=(verify.ReturnCode.SUCCESS, [], [], [], []),
            ):
                present.unlink()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        verify.verify_binaries_handler(args),
                        verify.ReturnCode.NO_BINARIES_MATCH,
                    )

                present.write_bytes(b"legitimate local binary")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        verify.verify_binaries_handler(args),
                        verify.ReturnCode.SUCCESS,
                    )
                self.assertIn(str(present), output.getvalue())
                self.assertIn(missing.name, output.getvalue())


def main():
    """Tests ordered roughly from faster to slower."""
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EmptyHashTests)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        sys.exit(1)

    expect_code(run_verify("", "pub", '0.32'), 4, "Nonexistent version should fail")
    expect_code(run_verify("", "pub", '0.32.awefa.12f9h'), 11, "Malformed version should fail")
    expect_code(run_verify('--min-good-sigs 20', "pub", "22.0"), 9, "--min-good-sigs 20 should fail")

    print("- testing verification (22.0-x86_64-linux-gnu.tar.gz)", flush=True)
    _220_x86_64_linux_gnu = run_verify("--json", "pub", "22.0-x86_64-linux-gnu.tar.gz")
    try:
        result = json.loads(_220_x86_64_linux_gnu.stdout.decode())
    except Exception:
        print("failed on 22.0-x86_64-linux-gnu.tar.gz --json:")
        print_process_failure(_220_x86_64_linux_gnu)
        raise

    expect_code(_220_x86_64_linux_gnu, 0, "22.0-x86_64-linux-gnu.tar.gz should succeed")
    v = result['verified_binaries']
    assert result['good_trusted_sigs']
    assert len(v) == 1
    assert v['bitcoin-22.0-x86_64-linux-gnu.tar.gz'] == '59ebd25dd82a51638b7a6bb914586201e67db67b919b2a1ff08925a7936d1b16'

    print("- testing verification (22.0)", flush=True)
    _220 = run_verify("--json", "pub", "22.0")
    try:
        result = json.loads(_220.stdout.decode())
    except Exception:
        print("failed on 22.0 --json:")
        print_process_failure(_220)
        raise

    expect_code(_220, 0, "22.0 should succeed")
    v = result['verified_binaries']
    assert result['good_trusted_sigs']
    assert v['bitcoin-22.0-aarch64-linux-gnu.tar.gz'] == 'ac718fed08570a81b3587587872ad85a25173afa5f9fbbd0c03ba4d1714cfa3e'
    assert v['bitcoin-22.0-osx64.tar.gz'] == '2744d199c3343b2d94faffdfb2c94d75a630ba27301a70e47b0ad30a7e0155e9'
    assert v['bitcoin-22.0-x86_64-linux-gnu.tar.gz'] == '59ebd25dd82a51638b7a6bb914586201e67db67b919b2a1ff08925a7936d1b16'


def run_verify(global_args: str, command: str, command_args: str) -> subprocess.CompletedProcess:
    maybe_here = Path.cwd() / 'verify.py'
    path = maybe_here if maybe_here.exists() else Path.cwd() / 'contrib' / 'verify-binaries' / 'verify.py'

    if command == "pub":
        command += " --cleanup"

    return subprocess.run(
        f"{path} {global_args} {command} {command_args}",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


def expect_code(completed: subprocess.CompletedProcess, expected_code: int, msg: str):
    if completed.returncode != expected_code:
        print(f"{msg!r} failed: got code {completed.returncode}, expected {expected_code}")
        print_process_failure(completed)
        sys.exit(1)
    else:
        print(f"✓ {msg!r} passed")


def print_process_failure(completed: subprocess.CompletedProcess):
    print(f"stdout:\n{completed.stdout.decode()}")
    print(f"stderr:\n{completed.stderr.decode()}")


if __name__ == '__main__':
    main()
