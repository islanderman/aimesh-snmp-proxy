"""Atomic, owner-only JSON state files under ``state_dir``.

A write goes to a temp file in the same directory, is fsynced, replaces the
target with ``os.replace``, then fsyncs the directory: a crash leaves the old
or the new file, never a torn one.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)
MAX_STATE_BYTES = 1 << 20


class StateFileError(RuntimeError):
    """A state file cannot be written."""


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        with contextlib.suppress(OSError):  # some filesystems refuse dir fsync
            os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path: Path, doc: Any) -> None:
    """Atomically replace ``path`` with ``doc`` as JSON, mode 0600."""
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
    directory = path.parent
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        _fsync_dir(directory)
    except OSError as exc:
        raise StateFileError(f"{path}: cannot write: {exc.strerror or exc}") from None


def read_json(path: Path) -> Any | None:
    """The parsed document, or None when the file is missing or unusable.

    An unusable file is renamed to ``<name>.corrupt`` and logged, so the
    caller starts fresh and an operator can still inspect what was there.
    """
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _LOG.error("state file %s unreadable: %s", path, exc.strerror or exc)
        return None
    try:
        if len(data) > MAX_STATE_BYTES:
            raise ValueError("too large")
        return json.loads(data.decode("utf-8"))
    except ValueError:  # JSONDecodeError and UnicodeDecodeError included
        aside = path.with_name(path.name + ".corrupt")
        with contextlib.suppress(OSError):
            os.replace(path, aside)
        _LOG.error("state file %s is corrupt; moved to %s, starting fresh", path, aside)
        return None
