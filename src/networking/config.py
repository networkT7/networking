from logging import getLevelName
from yaml import load, Loader

from networking.types import MasterConfig

with open("config.yaml") as f:
    global config
    config: MasterConfig = load(f.read(), Loader)

__conf = config["config"]

HOSTNAME = __conf["HOSTNAME"]
LOGGING_LEVEL: int = getLevelName(__conf["LOGGING_LEVEL"])
RECEIVE_SIZE = int(__conf["RECEIVE_SIZE"])
SOCKET_TIMEOUT = float(__conf["SOCKET_TIMEOUT"])
