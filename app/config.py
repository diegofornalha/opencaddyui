import configparser
import os

def get_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config