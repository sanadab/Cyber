import psutil
import json
import argparse
import time, sys
import requests
import subprocess
from termcolor import colored
from terminaltables import SingleTable
from cowpy import cow



COLORS = {\
"black":u"\u001b[30;1m",
"red":u"\u001b[31;1m",
"green":u"\u001b[32m",
"yellow":u"\u001b[33;1m",
"blue":u"\u001b[34;1m",
"magenta":u"\u001b[35m",
"cyan": u"\u001b[36m",
"white":u"\u001b[37m",
"yellow-background":u"\u001b[43m",
"black-background":u"\u001b[40m",
"cyan-background":u"\u001b[46;1m",
}

def colorText(text):
    for color in COLORS:
        text = text.replace("[[" + color + "]]", COLORS[color])
    return text

def ghostbusters():
    # Get a cow by name
    cow_cls = cow.get_cow('ghostbusters')
    cheese = cow_cls()
    msg = cheese.milk("VTotal Scan Tool")
    print(u"\u001b[31m" + msg)

def loading():
    print(u"\u001b[31;1mLoading...")
    for i in range(0, 100):
        time.sleep(0.1)
        width = (i + 1) / 4
        bar = "[" + "#" * int(width) + " " * int((25 - width)) + "]"
        sys.stdout.write(u"\u001b[1000D" + bar)
        sys.stdout.flush()
    print


def check_response_code(resp):
    if resp.status_code == 204:
        print("Request rate limit exceeded")
        sys.exit()


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", dest="QUIET", action="store_true", help="Do not print vendor analysis results")
    parser.add_argument("-p", "--positive", dest="POSITIVE", action="store_true", help="Show only positive results in vendor analysis")
    parser.add_argument("-o", "--out", dest="OUT", action="store_true", help="Save JSON response to a file")
    parser.add_argument("-c", "--clear", dest="CLEAR", action="store_true", help="Clear screen before printing vendor analysis results ")
    res = parser.parse_args()
    return res

def is_malicious(process):
    office_processes = ["excel.exe", "winword.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"]
    if process.name().lower() in office_processes or process.cpu_percent() > 50 or process.memory_percent() > 50:
        return True
    return False

def upload_to_virustotal(file_paths, api_key):
    res = arguments()
    results = []
    for file_path in file_paths:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': api_key}
        files = {'file': (file_path, open(file_path, 'rb'))}

        resp = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        check_response_code(resp)
        print("[*] Sent file to VT api")
        resource_hash = resp.json()['resource']
        params['resource'] = resource_hash
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:2.0b4) Gecko/20100818 Firefox/4.0b4"
        }
        resp = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=params, headers=headers)
        check_response_code(resp)
        if res.OUT:
            with open(res.OUT, "w+") as outfile:
                outfile.write(resp.text)
                outfile.close()
        print("[*] Received response\n")
        response_code = resp.json()['response_code']
        if (response_code == 1):
            positives = int(resp.json()['positives'])
            total = int(resp.json()['total'])
            if res.CLEAR:
                subprocess.call("clear", shell=True)
            detection_rate = round((positives / total) * 100, 2)
            attrs = []
            if int(detection_rate) in range(0, 20):
                color = 'blue'
            elif int(detection_rate) in range(20, 40):
                color = 'green'
            elif int(detection_rate) in range(40, 60):
                color = 'yellow'
            elif int(detection_rate) in range(60, 80):
                color = 'red'
            elif int(detection_rate) in range(60, 100):
                color = 'red'
                attrs = ['blink']

            scans = resp.json()['scans']
            table_data = [['--VENDOR--', '--STATUS--', '--RESULT--', '--UPDATE--']]
            for scan in scans:
                detected = colored("not detected", "red", attrs=["bold"])
                scan_result = "N/A"
                if scans[scan]['detected']:
                    detected = colored("detected", "green", attrs=["bold"])
                if scans[scan]['result'] != None:
                    scan_result = scans[scan]["result"]
                date = str(scans[scan]['update'])
                date = "{}-{}-{}".format(date[0:4], date[4:6], date[6:8])
                if (res.POSITIVE and scans[scan]["detected"]):
                    table_data.append([scan, detected, scan_result, date])
                elif not res.POSITIVE:
                    table_data.append([scan, detected, scan_result, date])
            table = SingleTable(table_data)
            table.inner_column_border = False
            table.outer_border = False
            table.justify_columns[1] = "center"
            if (not res.QUIET and len(table_data) != 1):
                print("\nVendors analysis results: " + file_path + "\n")
                print(table.table)
                results.append({"file_path": file_path, "scan_results": table_data})
        elif (response_code == -2):
            print("[*] Your resource is queued for analysis. Please submit your request in a moment again.\n")
        else:
            print(resp.json()['verbose_msg'])
    return results

def main():
    api_key = 'f20865137222a6d51e731f996f6f6259cf229c9519a53b755969395dd0f3f6e1'
    office_processes = ["excel.exe", "winword.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"]
    file_paths = []

    for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
        try:
            if is_malicious(process):
                print("Potentially malicious office process detected:")
                print(f"PID: {process.pid}")
                print(f"Name: {process.name()}")
                print(f"CPU Usage: {process.cpu_percent()}%")
                print(f"Memory Usage: {process.memory_percent()}%")
                print(f"Executable Path: {process.exe()}")
                print("=" * 50)
                print("")
                file_paths.append(process.exe())

                # Check for child processes
                for child in process.children(recursive=True):
                    print("Child process of", process.name(), "detected:")
                    print(f"PID: {child.pid}")
                    print(f"Name: {child.name()}")
                    print(f"CPU Usage: {child.cpu_percent()}%")
                    print(f"Memory Usage: {child.memory_percent()}%")
                    print(f"Executable Path: {child.exe()}")
                    print("=" * 50)
                    print("")
                    file_paths.append(child.exe())

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if file_paths:
        loading()
        scan_results = upload_to_virustotal(file_paths, api_key)
        if scan_results:
            for result in scan_results:
                 print("=" * 50)
    else:
        print("No potentially malicious processes found.")

if __name__ == "__main__":
    ghostbusters()

    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
