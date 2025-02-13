from requests import get, post
from pandas import DataFrame, json_normalize
from argparse import ArgumentParser
from urllib3 import disable_warnings
from json import dumps
from sys import exit
from yaml import safe_load
from pathlib import Path
from queue import Queue
from threading import Thread

disable_warnings()

exit_flag = False

class virustotal:
	def __init__(self, base_url, api_key):
		self.base_url = base_url
		self.api_key = api_key
	
	def get_results(self, hash):
		pass #TODO check the result & response back in JSON

parser = ArgumentParser(description='Generate Report from hash list through VirusTotal')
parser.add_argument('-f', '--file', type=str, required=True, help="File containing the hash list (MD5/SHA1/SHA256), separated by line")
args = parser.parse_args()

config = safe_load(open(Path(f"{__file__}", "..", "..", "config.yml"), 'r'))["virustotal"]
base_url = config["base_url"]
api_key_list = config["api_key"]

threads = []
work_queue = Queue()

for api_key in api_key_list:
	vt = virustotal(base_url, api_key)
	threads.append(vt)

hash_list = [hash.strip() for hash in open(args.file, 'r').read().splitlines()]

for hash in hash_list:
	work_queue.put(hash)

for t in threads:
	pass # TODO get the result with multi thread & put into DataFrame then export to csv