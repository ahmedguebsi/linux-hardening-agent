"""node_exporter textfile collector output.

The textfile collector is the standard way to publish metrics from a periodic
job: write ``*.prom`` files into a directory that node_exporter scrapes. It
decouples the agent's schedule (a systemd timer, hourly) from Prometheus'
schedule (every 15s), which is exactly right for an audit that is far too
expensive to run per-scrape.

Writes are **atomic**. node_exporter reads the directory on its own schedule; if
it catches a half-written file it drops the whole scrape and logs a parse error.
Writing to a temporary file and renaming makes a torn read impossible.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..logging_setup import get_logger

logger = get_logger("textfile")


class TextfileWriteError(OSError):
    """Raised when the textfile cannot be written."""


def write_textfile(path: str, content: str, *, mode: int = 0o644) -> None:
    """Atomically write exposition-format content to ``path``.

    The temporary file is created in the *same directory* as the target so the
    rename stays within one filesystem -- ``os.replace`` is only atomic within a
    single filesystem, and /tmp is frequently a separate mount.
    """
    target = Path(path)
    directory = target.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TextfileWriteError(f"cannot create textfile directory {directory}: {exc}") from exc

    if not content.endswith("\n"):
        content += "\n"

    handle = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=str(directory)
        )
        handle = os.fdopen(fd, "w", encoding="utf-8")
        handle.write(content)
        handle.flush()
        # fsync before rename: without it a host that loses power after the
        # rename can expose an empty file to the next scrape.
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, target)
        tmp_path = None
    except OSError as exc:
        raise TextfileWriteError(f"cannot write textfile {target}: {exc}") from exc
    finally:
        if handle is not None:
            handle.close()
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.warning("could not remove temporary file", extra={"path": tmp_path})

    logger.info(
        "textfile written", extra={"path": str(target), "bytes": len(content.encode("utf-8"))}
    )
