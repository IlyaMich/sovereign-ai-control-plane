"""Resolve operator-selected executables without searching the working directory."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_executable(command: str) -> str:
    if not command or command.startswith("-") or "\x00" in command:
        raise ValueError("Executable must be a name on PATH or an absolute path")
    path = Path(command)
    if not path.is_absolute():
        if path.name != command:
            raise ValueError("Relative executable paths are not allowed; use an absolute path")
        # Empty/relative PATH entries can execute files from an untrusted checkout.
        names = [command + ".exe"] if os.name == "nt" and not path.suffix else [command]
        found = None
        for entry in os.get_exec_path():
            directory = Path(entry)
            if not directory.is_absolute() or directory.resolve() == Path.cwd().resolve():
                continue
            for name in names:
                candidate = directory / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    found = candidate
                    break
            if found is not None:
                break
        if found is None:
            raise FileNotFoundError("Executable is unavailable on the trusted search path")
        path = found
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError("Executable is unavailable or not executable")
    if path.suffix.lower() in {".bat", ".cmd", ".ps1"}:
        raise ValueError("Shell script launchers are not supported")
    if os.name == "nt" and path.suffix.lower() != ".exe":
        raise ValueError("Windows executable must be an .exe file")
    # Keep the invocation path: resolving a venv Python symlink changes its environment.
    return str(path.absolute())
