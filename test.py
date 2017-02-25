from urllib.request import urlopen, build_opener
from urllib.parse import urlencode
from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired
from time import sleep
from os import remove


def parseCookie(header):
    h = header.split('=')
    data = ''
    for item in h[1:]:
        data = data + item
    d = {h[0]: data}
    return d
errcounter = 0
print("Removing old database")
try:
    remove('plugs.db')
except Exception as e:
    pass
print("Starting server.")
server = Popen(['python3', 'main.py', '--tests', 'True'],
               stdin=PIPE)
print("Sleeping 20 seconds to wait init")
sleep(20)
print("Checking index page...")
if 'WELCOME TO NTR PLUGIN DATABASE' in str(urlopen('http://127.0.0.1:8080/index').read(), 'utf-8').upper():
    print("Index is OK")
else:
    print("Index have problems!")
    errcounter = errcounter + 1
print("Logging in as admin...")
url = 'http://127.0.0.1:8080/login'
data = urlencode({'rtype': 'loginpg',
                  'email': 'test@test.test',
                  'pword': 'test'
                  }).encode('utf-8')
content = urlopen(url=url, data=data)
cookies = parseCookie(content.getheader('Set-Cookie'))
if 'AToken' in cookies:
    print("Received cookie,", cookies['AToken'])
    print("Login:OK")
    cookie = cookies['AToken']
else:
    print("Havent received cookie!")
    print("LOGIN:FAIL")
    errcounter = errcounter + 1
server.kill()
