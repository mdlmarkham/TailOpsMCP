from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from datetime import timezone, timezone
from typing import Any, Callable, Dict, Optional


class Snapshotter:
    """Periodically call a snapshot function and persist the results.

    The snapshot function should be a callable returning a JSON-serializable dict.
    Optionally, a simple alert callback can be provided which will be called when
    the snapshot meets an alert condition.
    """

    def __init__(
        self,
        snapshot_fn: Callable[[], Dict[str, Any]],
        out_dir: Optional[str] = None,
        interval: int = 300,
        alert_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.snapshot_fn = snapshot_fn
        self.interval = interval
        self.out_dir = out_dir or os.getenv("SYSTEMMANAGER_SNAPSHOT_DIR", "./snapshots")
        os.makedirs(self.out_dir, exist_ok=True)
        self.alert_fn = alert_fn
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def _loop(self):
        while self._running:
            try:
                snap = self.snapshot_fn()
                ts = datetime.now(timezone.utc).isoformat() + "Z"
                path = os.path.join(self.out_dir, f"snapshot-{ts}.json")
                # sanitize filename
                path = path.replace(":", "-")
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(
                        {"timestamp": ts, "snapshot": snap},
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
                if self.alert_fn:
                    try:
                        self.alert_fn(snap)
                    except Exception:
                        # don't allow alerts to stop the loop
                        pass
            except Exception:
                # ignore snapshot errors and continue
                pass
            await asyncio.sleep(self.interval)

    def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
