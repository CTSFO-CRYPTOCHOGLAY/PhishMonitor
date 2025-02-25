#Intel Phish by Mohammed Choglay
import urllib.request 
from urllib.request import urlopen
#import re (Not in use as of yet)
import os
import hashlib
from collections import defaultdict

print("[*] Starting Intel Phish")
print("[*] Gathering infromation from OpenPhish")

Open_Phish_URL="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
Open_Phish_URL_Path = "A:\\DEFSEC\\Bespoke Tools\\phinshing intel\\Reports\\"

def OpenPhish_Status_Check(Open_Phish_URL):
    try: 
        response = urllib.request.urlopen(Open_Phish_URL)
        if  response.getcode() == 200:
            print("[*] " + str(Open_Phish_URL) + " is online")#
            print("\n")

            with urlopen(Open_Phish_URL) as webpage:
                phish_data = webpage.read().decode()
            print(phish_data)
        
        save_data_txt = input("[*] Do you want to save the Y/N: ")
        save_data(save_data_txt_name)
        

    except Exception as e:
        print(f"[*] Error: {e}")
        return False

def save_data(save_data_txt):
    if save_data_txt == "Y":
        file_name=input("[*] Enter file name: ")
        with urlopen(Open_Phish_URL) as webpage:
                phish_data_wb = webpage.read()

        with open(Open_Phish_URL_Path + file_name, 'wb' ) as download:
                download.write(phish_data_wb)
    elif save_data_txt == "N": 
            print("false")
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
        print(f"Error: Directory '{directory}' does not exist.")
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



#OpenPhish_Status_Check(Open_Phish_URL)
scan_directory(Open_Phish_URL_Path)