import json
import logging
import re
import shutil
import subprocess  # nosec
from typing import Iterator, Optional, Sequence

from cachi2.core.config import get_config
from cachi2.core.errors import Cachi2Error

log = logging.getLogger(__name__)


def run_cmd(cmd: Sequence[str], params: dict) -> str:
    """
    Run the given command with provided parameters.

    :param iter cmd: iterable representing command to be executed
    :param dict params: keyword parameters for command execution
    :returns: the command output
    :rtype: str
    :raises CalledProcessError: if the command fails
    """
    params.setdefault("capture_output", True)
    params.setdefault("universal_newlines", True)
    params.setdefault("encoding", "utf-8")

    conf = get_config()
    params.setdefault("timeout", conf.subprocess_timeout)

    executable, *args = cmd
    executable_path = shutil.which(executable)
    if executable_path is None:
        raise Cachi2Error(
            f"{executable!r} executable not found in PATH",
            solution=(
                f"Please make sure that the {executable!r} executable is installed in your PATH.\n"
                "If you are using Cachi2 via its container image, this should not happen - please report this bug."
            ),
        )

    response = subprocess.run([executable_path, *args], **params)  # nosec

    try:
        response.check_returncode()
    except subprocess.CalledProcessError:
        log.error('The command "%s" failed', " ".join(cmd))
        _log_error_output("STDERR", response.stderr)
        if not response.stderr:
            _log_error_output("STDOUT", response.stdout)
        raise

    return response.stdout


def _log_error_output(out_or_err: str, output: Optional[str]) -> None:
    if output:
        log.error("%s:\n%s", out_or_err, output.rstrip())
    else:
        log.error("%s: <empty>", out_or_err)


def load_json_stream(s: str) -> Iterator:
    """
    Load all JSON objects from input string.

    The objects can be separated by one or more whitespace characters. The return value is
    a generator that will yield the parsed objects one by one.
    """
    decoder = json.JSONDecoder()
    non_whitespace = re.compile(r"\S")
    i = 0

    while match := non_whitespace.search(s, i):
        obj, i = decoder.raw_decode(s, match.start())
        yield obj
