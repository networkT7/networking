from queue import SimpleQueue


class TSDict[K, V]:
    __queue: SimpleQueue[tuple[K, V]] = SimpleQueue()

    def __contains__(self, key: K) -> bool:
        for k, _ in self:
            if k == key:
                return True
        return False

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

    def __setitem__(self, key: K, value: V) -> V | None:
        for _ in range(self.__queue.qsize()):
            k, v = self.__queue.get()
            if k == key:
                self.__queue.put((key, value))
                return v
            self.__queue.put((k, v))
        self.__queue.put((key, value))
        return None

    def get(self, key: K) -> V | None:
        for k, v in self:
            if k == key:
                return v
        return None

    def block_until(self, key: K) -> V:
        while True:
            k, v = self.__queue.get()
            if k == key:
                return v
            self.__queue.put((k, v))
