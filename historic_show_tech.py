#!/usr/bin/env python3

from jsonrpclib import Server
from pprint import pprint
from datetime import datetime
import socket
import os
import json

from cli import CliShell

shell = CliShell()

hostname = socket.gethostname()
timestamp = datetime.now().strftime("%Y-%m-%d.%H%M")
show_tech_filename = f'/usr/local/sampler/tech-support/{hostname}_tech-support_{timestamp}.txt'
shell.process_input_commands(f'show tech-support > {show_tech_filename}')[1]
os.system(f'gzip {show_tech_filename}')
