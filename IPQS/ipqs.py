from requests import get
from pandas import DataFrame
from argparse import ArgumentParser
from urllib3 import disable_warnings
from yaml import safe_load
from pathlib import Path
from datetime import datetime

disable_warnings()

full_result = []

parser = ArgumentParser(description='Generate Report from hash list through VirusTotal')
parser.add_argument('-f', '--file', type=str, required=True, help="File containing the IP list (IPV4/IPV6), separated by line")
args = parser.parse_args()

config = safe_load(open(Path(f"{__file__}", "..", "..", "config.yml"), 'r'))["ipqs"]
base_url = config["base_url"]
api_key = config["api_key"]

ip_list = open(args.f).read().split("\n")

for ip in ip_list:
	response = get(f"{base_url}{api_key}/{ip}").json()
	full_result.append(response)

now = int(datetime.now().timestamp())
df = DataFrame.from_dict(full_result)
df.to_csv(f"ipqs-{now}.csv")