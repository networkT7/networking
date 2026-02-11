class MAC_frame:
    __src: str
    __dst: str
    __length: int
    __data: str

    def __init__(self, src: str, dst: str, data: str):
        assert len(src) == 2
        assert len(dst) == 2

        length = len(data)
        assert length <= 256

        self.__src = src
        self.__dst = dst
        self.__length = length
        self.__data = data

    def __len__(self):
        return self.__length

    def __bytes__(self):
        return f"{self.__src}{self.__dst}{chr(self.__length)}{self.__data}".encode()
