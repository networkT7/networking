from threading import Lock, Event
from typing import Iterator


class TSDict[K, V]:
    """
    Thread-safe dictionary with blocking lookup support.
    """

    def __init__(self):
        self._lock = Lock()
        self._data: dict[K, V] = {}
        self._events: dict[K, Event] = {}

    def get(self, key: K) -> V | None:
        with self._lock:
            return self._data.get(key)

    def block_until(self, key: K, timeout: float = 10.0) -> V:
        """
        Block until key is set, then return its value.
        Raises TimeoutError if key is not set within timeout seconds.
        """
        with self._lock:
            if key in self._data:
                return self._data[key]
            if key not in self._events:
                self._events[key] = Event()
            event = self._events[key]

        if not event.wait(timeout=timeout):
            raise TimeoutError(f"block_until: key {key!r} not set within {timeout}s")

        with self._lock:
            return self._data[key]

    def __contains__(self, key: K) -> bool:
        with self._lock:
            return key in self._data

    def __iter__(self) -> Iterator[tuple[K, V]]:
        with self._lock:
            items = list(self._data.items())
        yield from items

    def __getitem__(self, key: K) -> V:
        with self._lock:
            if key in self._data:
                return self._data[key]
        raise KeyError(key)

    def __setitem__(self, key: K, value: V):
        with self._lock:
            self._data[key] = value
            # Unblock any thread waiting on this key
            if key in self._events:
                self._events[key].set()
                del self._events[key]
