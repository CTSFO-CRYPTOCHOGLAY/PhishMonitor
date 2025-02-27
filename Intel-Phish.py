# Intel Phish by Mohammed Choglay
import urllib.request
from urllib.request import urlopen

# import re (Not in use as of yet)
import os
import hashlib
from collections import defaultdict
from dotenv import load_dotenv
import time


# Data being loaded from .env
load_dotenv()
Open_Phish_URL = os.getenv("Open_Phish_URL")
directory = os.getenv("Open_Phish_Report_Path")
VT_API = os.getenv("VT_API")


print("[*] Starting Intel Phish")
print("[*] Gathering infromation from OpenPhish")


def OpenPhish_Status_Check(Open_Phish_URL):
    try:
        response = urllib.request.urlopen(Open_Phish_URL)
        if response.getcode() == 200:
            print("[*] " + str(Open_Phish_URL) + " is online")  #
            print("\n")

            with urlopen(Open_Phish_URL) as webpage:
                phish_data = webpage.read().decode()
            print(phish_data)

        save_data_txt_name = input("[*] Do you want to save the Y/N: ")
        save_data(save_data_txt_name)

    except Exception as e:
        print(f"[*] Error: {e}")
        return False


def save_data(save_data_txt):
    if save_data_txt == "Y":
        file_name = input("[*] Enter file name: ")
        with urlopen(Open_Phish_URL) as webpage:
            phish_data_wb = webpage.read()

        with open(directory + file_name, "wb") as download:
            download.write(phish_data_wb)
    elif save_data_txt == "N":
        print("[*] Program closed.")
    else:
        print("[!] Invalid Input")


def hashing(Open_Phish_URL_Path, algorithm="sha256"):
    hashing = hashlib.new(algorithm)
    with open(Open_Phish_URL_Path, "rb") as f:
        while chunk := f.read(8192):
            hashing.update(chunk)
    return hashing.hexdigest()


def scan_directory(directory, algorithm="sha256"):
    """Scans a directory, hashes files, and counts occurrences of hashes."""
    if not os.path.exists(directory):
        print(f"[!] Error: Directory '{directory}' does not exist.")
        return

    hash_count = defaultdict(int)  # Stores hash counts
    file_hashes = {}  # Stores file hash mappings

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hashing(file_path, algorithm)

            file_hashes[file_path] = file_hash
            hash_count[file_hash] += 1  # Count occurrences

    # Output results
    print("\n[*] File Hashes:")
    for file_path, file_hash in file_hashes.items():
        print(f"{file_path}: {file_hash}")

    print("\n[*] Hash Occurrences:")
    for file_hash, count in hash_count.items():
        print(f"{file_hash}: {count} time(s)")


def url_scan_virustotal(url):
    url_scan = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API}
    data = {"url": url}

    try:
        response = requests.post(url_scan, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()["data"]["id"]
        else:
            return None
    except Exception as e:
        return None


#OpenPhish_Status_Check(Open_Phish_URL)
scan_directory(directory)