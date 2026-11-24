"""Live WAL-safe SQLite backup to a disposable DELETE-mode snapshot for offline review.

The source audit database is never rewritten or checkpointed by this benchmark.
The snapshot is created by the running control-plane process, then verified in a
network-disabled read-only audit-reviewer container, and finally removed.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
import uuid

SNAPSHOT_PREFIX = ".bench-audit-snapshot-"
SNAPSHOT_RE = re.compile(r"^\.bench-audit-snapshot-[0-9a-f]{32}\.sqlite$")

# Executed inside existing approved control-plane container via `compose exec -T`.
# Only stdlib dependencies; nothing added to the signed image.
CREATE_SNAPSHOT_CODE = r"""import os
import sqlite3
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
if not (target.name.startswith('.bench-audit-snapshot-') and target.suffix == '.sqlite'
        and target.parent == source.parent and source.is_file()):
    raise RuntimeError('Unsafe audit snapshot source or target')
# Prevent overwriting existing files; reject symlink redirection.
fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
source_conn = None
target_conn = None
try:
    source_conn = sqlite3.connect('file:' + str(source) + '?mode=ro', uri=True, timeout=10)
    target_conn = sqlite3.connect(str(target), timeout=10)
    source_conn.backup(target_conn, pages=1000, sleep=0.05)
    # SQLite backup copies WAL journal-mode metadata. Normalize the COPY only.
    mode = target_conn.execute('PRAGMA journal_mode=DELETE').fetchone()[0]
    if mode.lower() != 'delete':
        raise RuntimeError('Snapshot could not be normalized to DELETE mode')
    target_conn.commit()
    print('SNAPSHOT_READY', flush=True)
finally:
    if target_conn is not None:
        target_conn.close()
    if source_conn is not None:
        source_conn.close()
"""

# Executed only on the temporary snapshot path, never on the audit source path.
DELETE_SNAPSHOT_CODE = r"""from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
if snapshot.parent != source.parent or not re.fullmatch(r'\.bench-audit-snapshot-[0-9a-f]{32}\.sqlite', snapshot.name):
    raise RuntimeError('Unsafe snapshot cleanup request')
for name in (str(snapshot), str(snapshot) + '-wal', str(snapshot) + '-shm', str(snapshot) + '-journal'):
    p = Path(name)
    if p.is_symlink():
        raise RuntimeError('Refusing to remove symlinked benchmark artifact')
    p.unlink(missing_ok=True)
print('SNAPSHOT_REMOVED', flush=True)
"""


def snapshot_paths(control_db: str, reviewer_db: str, *, identifier: str | None = None) -> tuple[str, str]:
    """Use matching filenames in the shared audit volume, regardless of mount target."""
    tag = uuid.uuid4().hex if identifier is None else identifier
    if not re.fullmatch(r"[0-9a-f]{32}", tag):
        raise ValueError("Invalid snapshot identifier")
    for path in (control_db, reviewer_db):
        if not PurePosixPath(path).is_absolute():
            raise ValueError("Audit database paths must be absolute container paths")
    filename = SNAPSHOT_PREFIX + tag + ".sqlite"
    return (str(PurePosixPath(control_db).with_name(filename)),
            str(PurePosixPath(reviewer_db).with_name(filename)))
