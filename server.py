import json
import time
import requests
from pathlib import Path
from sys import argv
from subprocess import run

def main():
    config = json.loads(Path(argv[1]).read_text())
    key = config["judger_key"]
    server = config["server"]
    sandbox = config["sandbox"]
    cgroup = config["cgroup"]
    judger_path = config["judger_path"]
    while True:
        r = requests.get(server + "/api/v1/get-submission")
        if r.status_code != 200:
            print(r.status_code)
            time.sleep(1)
            continue
        j = r.json()
        id = j["id"]
        with open("task.json", "wb") as f:
            f.write(r.content)
        r = requests.post(server + "/api/v1/update-submission", data={
            "submission": id,
            "key": key,
            "status": "assigned",
            "memory": "0",
            "time": "0"
        })
        r.raise_for_status()
        proc = run([judger_path, sandbox, cgroup, "task.json"], capture_output=True)
        res = json.loads(proc.stdout.decode("utf-8"))
        r = requests.post(server + "/api/v1/update-submission", data={
            "submission": id,
            "key": key,
            "status": res["verdict"],
            "memory": str(res["memory"]),
            "time": str(res["time"])
        })
        r.raise_for_status()
        

if __name__ == "__main__":
    main()
