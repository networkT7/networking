from queue import SimpleQueue


class TSDict[K, V]:
    __queue: SimpleQueue[tuple[K, V]] = SimpleQueue()

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

    def get(self, key: K) -> V | None:
        for k, v in self:
            if k == key:
                return v
        return None

    def block_until(self, key: K) -> V:
        while True:
            k, v = self.__queue.get()
            self.__queue.put((k, v))
            if k == key:
                return v
