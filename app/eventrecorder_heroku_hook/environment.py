import datetime
import getpass
import os
import pathlib
import shutil
import socket
import sys

import requests

from simple_config import YamlConfig
from simple_config.logging_tools import init_logger
from simple_config.singleton import Singleton

PRIMARY_MODULE_DIR = pathlib.Path(__file__).parent
APP_ROOT = PRIMARY_MODULE_DIR.parent
PROJECT_ROOT = APP_ROOT.parent


class Env(metaclass=Singleton):
    PROJECT_NAME = PRIMARY_MODULE_DIR.name
    CONFIG_DIR_PATH = APP_ROOT.joinpath("config")
    SECRETS_DIR_PATH = pathlib.Path(f"/secrets/{PROJECT_NAME}")

    logger = None
    config = None

    def __init__(self):
        self.process_name = pathlib.Path(sys.argv[0]).stem
        self.user_name = getpass.getuser()
        self.host_name = socket.gethostname()
        self.runtime_start = datetime.datetime.now

        mode_env_var = self.PROJECT_NAME.upper() + "_MODE"
        mode = os.environ.get(mode_env_var)
        mode_config_file_name = f"{mode}.yaml"
        mode_config_file_path = self.CONFIG_DIR_PATH.joinpath(mode_config_file_name)
        potential_secret_mode_config_override_file_path = self.SECRETS_DIR_PATH.joinpath(mode_config_file_name)

        if potential_secret_mode_config_override_file_path.exists():
            shutil.copy(
                potential_secret_mode_config_override_file_path.as_posix(),
                mode_config_file_path.as_posix()
            )

        self.config = YamlConfig(self.PROJECT_NAME, process_name=self.process_name)
        self.config.app_dir = APP_ROOT.as_posix()
        self.config.project_dir = PROJECT_ROOT.as_posix() if (PROJECT_ROOT.name == self.PROJECT_NAME) else APP_ROOT.as_posix()
        self.config.load(include_user_overrides=True)

        self.logger = init_logger(self.config.logging.logger_type, self.config.logging.logger_options)
        self.session = requests.Session()
        self.session.mount("http://", requests.adapters.HTTPAdapter(pool_maxsize=self.config.eventrecorder_conn_pool_size))
        self.session.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=self.config.eventrecorder_conn_pool_size))
