"""
monitor.py — Tails the Nginx JSON access log line by line.

Concept: We open the log file, seek to its end, and yield each new line as
it appears. This works just like `tail -f` in the shell. When Nginx rotates
the log (renaming it and creating a new file), we detect the inode change
and reopen the file so we don't miss events.
"""

import os
import time
import json


def tail_log(filepath):
    """
    Generator that yields parsed JSON events from the log file.
    Yields one dict per log line. Skips malformed lines silently.
    """
    # Wait for the file to exist (Nginx may not have created it yet).
    while not os.path.exists(filepath):
        print(f"[monitor] Waiting for log file {filepath} ...")
        time.sleep(1)

    # Open the file and remember its inode so we can detect rotation.
    f = open(filepath, 'r')
    f.seek(0, 2)  # seek to end of file - 2 means SEEK_END
    inode = os.fstat(f.fileno()).st_ino

    print(f"[monitor] Tailing {filepath} (inode {inode})")

    while True:
        line = f.readline()
        if not line:
            # No new data right now — sleep briefly to avoid pegging the CPU.
            time.sleep(0.1)

            # Check if the file was rotated (inode changed) or truncated.
            try:
                if os.stat(filepath).st_ino != inode:
                    print("[monitor] Log rotated, reopening")
                    f.close()
                    f = open(filepath, 'r')
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                # File momentarily gone during rotation — wait for it back.
                time.sleep(1)
            continue

        # Parse JSON. If it fails (partial line, malformed), skip silently.
        try:
            event = json.loads(line.strip())
            yield event
        except json.JSONDecodeError:
            # Malformed line — log to stderr but keep going.
            continue
