class FakeClock:
    """
    Deterministic injectable monotonic clock for testing expiration,
    time-based authorization hold expirations, and rate limits.
    """

    def __init__(self, initial_time: float = 1700000000.0):
        self._current_time: float = float(initial_time)

    def now(self) -> float:
        """Return the current simulated timestamp in seconds."""
        return self._current_time

    def advance(self, seconds: float) -> float:
        """Advance time forward by the given number of seconds and return the new timestamp."""
        if seconds < 0:
            raise ValueError(f"Cannot rewind time: {seconds} seconds requested")
        self._current_time += seconds
        return self._current_time

    def set(self, timestamp: float) -> float:
        """Set the clock to a specific timestamp (must be >= current timestamp)."""
        if timestamp < self._current_time:
            raise ValueError(f"Cannot set time backwards: {timestamp} < {self._current_time}")
        self._current_time = float(timestamp)
        return self._current_time

    def reset(self, initial_time: float = 1700000000.0) -> None:
        """Reset the clock to a given timestamp (default 1700000000.0)."""
        self._current_time = float(initial_time)
