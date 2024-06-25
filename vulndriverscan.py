import urllib.request
import json
import hashlib
import os
import argparse
import pathlib
import subprocess

with urllib.request.urlopen("https://www.loldrivers.io/api/drivers.json") as response:
    LOLDrivers_data = response.read()

def scan_running_drivers() -> str:
    ps = ["powershell.exe", "-Command", "driverquery.exe /v /fo CSV | ConvertFrom-CSV | Where-Object { $_.'State' -eq 'Running' } | Select-Object  -ExpandProperty 'Path'"]
    result = subprocess.run(ps, capture_output=True, text=True, shell=False)
    driver_path_output = result.stdout
    return driver_path_output

def compute_sha256(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        bytes_chunk = 0
        while bytes_chunk := f.read(4096):  # read bytes in 0x1000 (4096) increments
            sha256_hash.update(bytes_chunk)
    return sha256_hash.hexdigest()

def scan_vuln_driver_hash(data: str, hash_lookup: str) -> bool:
    data = json.loads(data)
    found_hash = False
    for driver in data:
        for vuln_samples in driver.get("KnownVulnerableSamples", []):
            # if vuln_samples.get('LoadsDespiteHVCI', []) == "TRUE":  # This filter is in place because the driver won't load if HVCI is enabled (which it is by default on all Windows systems)
            if hash_lookup in vuln_samples.get("SHA256", []):
                print(f"found a vulnerable driver hash,  Filename: {vuln_samples.get('Filename', [])}, "
                      f"Authentihash: {vuln_samples.get('Authentihash', [])}")
                found_hash = True
                return found_hash

def compute_hash_and_scan_json(file_path_list: list):
    for file_path in file_path_list:
        file_hash = compute_sha256(str(file_path))
        print(f"filepath: {str(file_path)}, file hash: {file_hash}")
        if not scan_vuln_driver_hash(LOLDrivers_data, file_hash):
            print(f"vuln driver hash not found for {str(file_path)}")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', "--path", )
    parser.add_argument('-srd', "--srd")
    args = parser.parse_args()
    path_input = args.path
    is_scan_running_drivers = args.srd

    if not is_scan_running_drivers:
        if path_input is None:
            print("path not specified")
            return

        if not os.path.exists(path_input):
            print("not a valid path")
            return

    if is_scan_running_drivers:
        print("scanning running drivers\n")
        output_list = list(scan_running_drivers().strip().split('\n'))
        compute_hash_and_scan_json(output_list)
    else:
        file_recursive = pathlib.Path(path_input)
        file_recursive.rglob("*.sys")
        file_recursive_list = list(file_recursive.rglob('*.sys'))
        print(f"found driver file(s): {file_recursive_list}")
        compute_hash_and_scan_json(file_recursive_list)


main()