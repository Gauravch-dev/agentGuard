"""Bounded in-process request windows for the single-worker loopback MVP."""

from collections import deque


class RequestLimiter:
    def __init__(self, capacity: int = 4096) -> None:
        self.capacity = capacity
        self.windows: dict[str, deque[float]] = {}

    def allow(self, key: str, budget: int, stamp: float) -> bool:
        if key not in self.windows and len(self.windows) >= self.capacity:
            expired = [
                k for k, window in self.windows.items() if not window or window[-1] <= stamp - 60
            ]
            for expired_key in expired:
                del self.windows[expired_key]
            if len(self.windows) >= self.capacity:
                return False
        window = self.windows.setdefault(key, deque())
        while window and window[0] <= stamp - 60:
            window.popleft()
        if len(window) >= budget:
            return False
        window.append(stamp)
        return True
