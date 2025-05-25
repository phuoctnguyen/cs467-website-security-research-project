import hashlib
import json
import os


# code adapted from: https://chatgpt.com/share/68326fb2-97e4-800c-8b80-b59f9dd746d8
def create_rainbow_table(rainbow_table_filepath, rockyou_filepath):
    # check if rainbow table exists
    if os.path.exists(rainbow_table_filepath):
        print("Rainbow table exists.")
    else:
        print("\nRainbow table does not exist. Creating it...")

        # read & clean passwords
        with open(rockyou_filepath, "r", errors="ignore") as pwd_file:
            rockyou_pwds_raw = pwd_file.readlines()

        # generate hashes & create rainbow table
        md5_hash_table = {}     # dictionary to store hashes
        for raw_pwd in rockyou_pwds_raw:
            pwd_clean = raw_pwd.rstrip()    # remove trailing newline character
            pwd_bytes = pwd_clean.encode('utf-8')   # convert password to array of bytes
            md5_hash = hashlib.md5(pwd_bytes).hexdigest()   # generate hash
            md5_hash_table[md5_hash] = pwd_clean    # store as {hash: password}

        # create & write contents to rainbow table as JSON file
        try:
            with open(rainbow_table_filepath, "w") as json_file:
                json.dump(md5_hash_table, json_file)
            print("Rainbow table created.")
        except Exception as e:
            print(f"Error creating the rainbow table:", e)


def time_str(secs, file_name, option):
    """Return a time string from given parameters."""

    if option == '1':
        return f"{(secs * 1000):.2f} milliseconds"
    if option == '2':
        return f"{(secs / 60):.2f} minutes" if file_name == "rockyou.txt" else f"{secs:.2f} seconds"
    else:
        return f"{(secs / 3600):.2f} hours" if file_name == "rockyou.txt" else f"{(secs / 60):.2f} minutes"
