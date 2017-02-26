from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired, call
from os import remove, system
from os.path import exists
from time import sleep
from sys import exit
if exists('plugs.db'):
    remove('plugs.db')
server = Popen(['python3', 'main.py', '--tests', 'True', '-p', '8080'],
               stdin=PIPE,
               stdout=DEVNULL,
               stderr=DEVNULL)
print("Waiting 10 seconds to init server fully")
sleep(10)
try:
    server.wait(1)
except TimeoutExpired:
    retval = None
    retval = call(['python3', '-m', 'pytest'])
    server.kill()
    exit(retval)
else:
    exit('Server error!')
