from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired, call
from urllib.request import urlopenS
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
print("Waiting init of server")
while 1:
    try:
        urlopen('http://127.0.0.1:8080')
    except Exception:
        sleep(0.5)
        try:
            server.wait(0.1)
        except TimeoutExpired:
            pass
        else:
            print("Server hasnt started up properly!")
            exit('Tests blacked out!')
    else:
        print("Server started! Beggining tests!")
        break

retval = None
retval = call(['python3', '-m', 'pytest'])
server.kill()
exit(retval)