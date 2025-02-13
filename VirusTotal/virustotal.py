from requests import get
from pandas import DataFrame
from datetime import datetime
from time import sleep
from queue import Queue
from yaml import safe_load
from pathlib import Path
from threading import Thread

config = safe_load(open(Path(Path(__file__).parent.parent, "config.yml"), 'r'))["virustotal"]
vt_api_key_list = config["api_key"]
vt_base_url = config["base_url"]
thread_exit_flag = 0

all_result_df = DataFrame({
	"initial_hash": [],
	"sha256": [],
	"trendmicro": [],
	"total_malicious": []
})

class VT(Thread):
	def __init__(self, vt_api_key):
		Thread.__init__(self)
		self.vt_api_key = vt_api_key
	def run(self):
		print("Initializing " + self.vt_api_key)
		process_data(self.vt_api_key)
		print("Exiting " + self.vt_api_key)

# helper function to process data
def process_data(vt_api_key):
	vt_headers = {
		"x-apikey": vt_api_key,
		"Accept": "application/json"
	}

	count = 0
	inital_time = datetime.now()
	while not thread_exit_flag:
		if not work_queue.empty():
			initial_hash = work_queue.get().strip()
			if len(initial_hash) > 0 and initial_hash not in all_result_df.values:
				while True:
					try:
						response = get(f"{vt_base_url}/files/{initial_hash}", headers=vt_headers, verify=False).json()
						break
					except:
						sleep(1)
				try:
					sha256_result = response["data"]["attributes"]["sha256"]
					trendmicro = response["data"]["attributes"]["last_analysis_results"]["TrendMicro"]["category"]
					total_malicious = response["data"]["attributes"]["last_analysis_stats"]["malicious"]
				except:
					sha256_result = ""
					trendmicro = ""
					total_malicious = ""

				result = {
					"initial_hash": initial_hash,
					"sha256": sha256_result,
					"trendmicro": trendmicro,
					"total_malicious": total_malicious
				}
				while True:
					try:
						all_result_df.loc[len(all_result_df)] = result
						break
					except:
						sleep(1)
				count += 1
				if count == 4 and not work_queue.empty():
					current_time = datetime.now()
					time_diff = current_time - inital_time
					cool_off = 60-time_diff.seconds
					print(f"{vt_api_key} API done for {initial_hash}, sleep for {cool_off} seconds")
					sleep(cool_off)
					count = 0
					inital_time = datetime.now()
				else:
					print(f"{vt_api_key} API done for {initial_hash}")

if __name__ == "__main__":
	hash_list = open(Path(Path(__file__).parent, "hashlist.txt"), "r").read().splitlines()
	hash_list = list(dict.fromkeys(hash_list))
	work_queue = Queue(len(hash_list))
	for hash in hash_list:
		work_queue.put(hash)

	threads = []

	# Create new threads
	for vt_api_key in vt_api_key_list:
		thread = VT(vt_api_key)
		threads.append(thread)

	for t in threads:
		t.start()

	# Wait for the queue to empty
	while not work_queue.empty():
		pass

	# Notify threads it's time to exit
	thread_exit_flag = 1

	# Wait for all threads to complete
	for t in threads:
		t.join()
	year = datetime.now().year
	month = "%02d" % datetime.now().month
	day = "%02d" % datetime.now().day
	all_result_df.to_csv(f"vt_result-{year}-{month}-{day}.csv")
	print("Fully Completed!") 