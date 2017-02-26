from subprocess import Popen, DEVNULL, TimeoutExpired
from urllib.request import urlopen
from os import remove
from os.path import exists
from time import sleep
from sys import exit
from time import time
import pytest
if exists('plugs.db'):
    remove('plugs.db')
server = Popen(['python3', 'main.py', '--tests', 'True', '-p', '8080'],
               stdin=DEVNULL,
               stdout=DEVNULL,
               stderr=DEVNULL)
start_t = time()
while 1:
    try:
        urlopen('http://127.0.0.1:8080')
    except Exception:
        sleep(0.01)
        try:
            server.wait(0.1)
        except TimeoutExpired:
            pass
        else:
            print("Server hasnt started up properly!")
            exit('Tests blacked out!')
    else:
        end_t = time()
        break


class initinfo:
    def pytest_report_header(self):
        return ("Server started in %s seconds" % (end_t - start_t))


retval = pytest.main(plugins=[initinfo()])
server.kill()
exit(retval)
