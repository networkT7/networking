from pathlib import Path
from yaml import load, Loader

from networking.types import Config

_config_path = Path(__file__).resolve().parent.parent.parent / "config.yaml"

with open(_config_path) as f:
    global config
    config: Config = load(f.read(), Loader)

__conf = config["config"]

HOSTNAME = __conf["HOSTNAME"]
LOGGING_LEVEL = __conf["LOGGING_LEVEL"]
RECEIVE_SIZE = int(__conf["RECEIVE_SIZE"])
SOCKET_TIMEOUT = float(__conf["SOCKET_TIMEOUT"])
