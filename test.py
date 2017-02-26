from urllib.request import urlopen, build_opener
from urllib.parse import urlencode
from urllib.error import HTTPError
from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired
from time import sleep
from os import remove
from sys import exit


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
server = Popen(['python3', 'main.py', '--tests', 'True', '-p', '8080'],
               stdin=PIPE,
               stdout=DEVNULL,
               stderr=DEVNULL)
print("Sleeping 20 seconds to wait init")
sleep(20)
print("Checking index page...")
try:
    if 'WELCOME TO NTR PLUGIN DATABASE' in str(urlopen('http://127.0.0.1:8080/index').read(), 'utf-8').upper():
        print("Index:OK")
    else:
        print("Index:FAIL(wrong page)")
        errcounter = errcounter + 1
except HTTPError as e:
    print("Index:FAIL(server returned non-200 statuscode:%s)" % (e.code))
    errcounter = errcounter + 1
print("Logging in as admin...")
url = 'http://127.0.0.1:8080/login'
data = urlencode({'rtype': 'loginpg',
                  'email': 'test@test.test',
                  'pword': 'test'
                  }).encode('utf-8')
try:
    content = urlopen(url=url, data=data)
except HTTPError as e:
    print("Login:FAIL(non-200 status code:%s)" % (e.code))
    print("The next tests wont happen: Add, Edit, Remove, Logout")
else:
    cookies = content.getheader('Set-Cookie')
    if 'AToken' in cookies:
        print("Login:OK")
        opener = build_opener()
        opener.addheaders.append(('Cookie', cookies))
        try:
            addtest = opener.open('http://127.0.0.1:8080/additem?name=Test+plugin&desc=Test&ver=0&developer=Developer&tid=00040000001A3200%3B00040000001A4100&devsite=http%3A%%2F%%2Fexample.com&link=http%3A%%2F%%2Fexample.com%%2Fplg&pic=&ctype=universal&add=1')
        except HTTPError as e:
            print("Add:FAIL(non-200 status code:%s" % e.code)
            errcounter = errcounter + 1
        else:
            print("Add:OK")
    else:
        print("Login:FAIL(No cookies received)")
        print("The next tests wont happen: Add, Edit, Remove, Logout")
        errcounter = errcounter + 1
server.kill()
if errcounter == 0:
    print("Tests were completed succesfully.")
    exit()
else:
    print("There were an errors during tests.")
    print("Error count:", errcounter)
    exit("Failed.")
