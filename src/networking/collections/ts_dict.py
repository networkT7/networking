from queue import SimpleQueue


class TSDict[K, V]:
    """
    A thread safe-ish dictionary implementation built for multi-threaded classes
    """

    __queue: SimpleQueue[tuple[K, V]] = SimpleQueue()

    def get(self, key: K) -> V | None:
        """
        Attempt to get the value associated with the key without waiting
        """
        for k, v in self:
            if k == key:
                return v
        return None

    def block_until(self, key: K) -> V:
        """
        Block execution until the required mapping is created, and return the associated value
        """
        while key not in self:
            pass
        return self[key]

    def __contains__(self, key: K) -> bool:
        v = self.get(key)
        return True if v else False

    def __iter__(self):
        for _ in range(self.__queue.qsize()):
            e = self.__queue.get()
            self.__queue.put(e)
            yield e

    def __getitem__(self, key: K) -> V:
        v = self.get(key)
        if v:
            return v
        raise KeyError

    def __setitem__(self, key: K, value: V):
        for _ in range(self.__queue.qsize()):
            k, _ = self.__queue.get()
            if k == key:
                self.__queue.put((key, value))
        self.__queue.put((key, value))
