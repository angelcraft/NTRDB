from http.server import HTTPServer, BaseHTTPRequestHandler
import pickle
from os.path import exists
import datetime
from urllib.parse import unquote
from uuid import uuid4
from json import dumps
import hashlib
from socketserver import ThreadingMixIn
import threading
from subprocess import check_output
import xml.etree.ElementTree as ET
from urllib.request import urlopen
from validators import url
if exists('plugins.pickle'):
    with open('plugins.pickle', 'rb') as f:
        plugins = pickle.load(f)
else:
    with open('plugins.pickle', 'wb') as f:
        pickle.dump(
            {
                'ids': {0: None},
            },
            f)
    print(
        "Plugin database wasnt found. The one were created, to apply it please restart NTRDB")
    raise SystemExit
with open('html/index.html') as f:
    index = f.read()
with open('html/base.html') as f:
    base = f.read()
with open('html/message.html') as f:
    messagehtml = f.read()
with open('html/addfile.html') as f:
    addfile = f.read()
with open('html/remove.html') as f:
    remove = f.read()
print("Pages loaded, loading 3dsdb")
titles = ET.fromstring(
    str(urlopen('http://3dsdb.com/xml.php').read(), 'utf-8'))
print("3DSDB loaded, optimising it...")
tids = []
for item in titles:
    tids.append([item[1].text, item[8].text])
del titles
print("DONE!")
version = str(
    check_output('git log -n 1 --pretty=format:"%h"', shell=True), 'utf-8')


def parseURL(path):
    try:
        data = path.split("?")[1].split("&")
    except Exception:
        return {}
    else:
        parsed = {}
        for item in data:
            i = item.split("=")
            parsed[i[0]] = unquote(i[1].replace('+', ' '))
        return parsed


def getgamebytid(tid):
    ok = False
    for item in tids:
        if item[1] == tid:
            return item[0]
            ok = True
    if not ok:
        return "Game TitleID hasnt found in 3DSDB :("


def computeMD5hash(string):
    m = hashlib.md5()
    m.update(string.encode('utf-8'))
    return m.hexdigest()


class myHandler(BaseHTTPRequestHandler):

    def api(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        apidata = {}
        copy = dict(plugins)
        for item in copy['ids']:
            if not item == 0:
                plugin = copy['ids'][item]
                apidata[item] = plugin
                try:
                    del apidata[item]["__removal_id"]
                except Exception:
                    pass
                else:
                    pass
        self.wfile.write(bytes(dumps(apidata), 'utf-8'))

    def index(self):
        table = ""
        message = ""
        isSearch = False
        path = self.path[1:]
        if not len(path.split("?")) == 1:
            parsed = parseURL(self.path)
            if 'search' in parsed:
                query = parsed['search']
                isSearch = True
                results = []
                for item in plugins['ids']:
                    if not item == 0:
                        plugin = plugins['ids'][item]
                        if plugin['TitleID'].startswith(query) or query in plugin['name']:
                            results.append(plugin)
                for item in results:
                    if not item["TitleID"] == "Not game":
                        name = getgamebytid(item["TitleID"])
                    else:
                        name = ""
                    table = table + "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href=\"%s\">Download</a></td></tr>" % (
                        item["TitleID"],
                        name,
                        item["name"],
                        item["added"],
                        item['plg']
                    )

        if not isSearch:
            for item in plugins['ids']:
                if not item == 0:
                    item = plugins['ids'][item]
                    if not item["TitleID"] == "Not game":
                        name = getgamebytid(item["TitleID"])
                    else:
                        name = ""
                    table = table + "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href=\"%s\">Download</a></td></tr>" % (
                        item["TitleID"],
                        name,
                        item["name"],
                        item["added"],
                        item['plg']
                    )
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        page = base % (version, index % (table))
        self.wfile.write(bytes(page, 'utf-8'))

    def additem(self):
        parsed = parseURL(self.path)
        print(parsed)
        if 'plg' in parsed:
                plgp = parsed["plg"]
                titleid = parsed['titid']
                plugname = parsed['name']
                badreq = False
                if plgp == "":
                    message = "You havent entered path to plg file!"
                    badreq = True
                    succ = False
                if titleid == "" and not 'isNotGame' in parsed:
                    message = "You havent entered game's TitleID!"
                    badreq = True
                    succ = False
                if plugname == "":
                    message = "You havent entered plugin's name!"
                    badreq = True
                    succ = False
                elif not len(titleid) == 16 and not 'isNotGame' in parsed:
                    message = "You entered bad TitleID!"
                    badreq = True
                    succ = False
                if not url(unquote(plgp)) == True:
                    message = "You entered bad plugin download URL!"
                    badreq = True
                    succ = False
                plgp = unquote(plgp)
                for item in plugins['ids']:
                    if not item == 0:
                        if plugins['ids'][item]['plg'] == plgp:
                            badreq = True
                            succ = False
                            message = "Plugin already exists!"
                            break
                if not badreq:
                    now = datetime.datetime.now()
                    removal_id = str(uuid4())
                    if 'isNotGame' in parsed:
                        titleid = 'Not game'
                    plugins['ids'][max(plugins['ids']) + 1] = {'TitleID': titleid,
                                                               'name': plugname.replace('+', ' '),
                                                               'plg': plgp,
                                                               'added': now.strftime("%Y-%m-%d %H:%M"),
                                                               'timestamp': now.timestamp(),
                                                               'version': ver,
                                                               'site': site
                                                               }
                    with open('plugins.pickle', 'wb') as f:
                        pickle.dump(plugins, f)
                    message = "Added your plugin!".format(
                        removal_id)
                    succ = True
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = base % (version, addfile)
            self.wfile.write(bytes(page, 'utf-8'))
    # Handler for the GET requests
    def do_GET(self):
        if self.path.startswith('/api'):
            self.api()
        elif self.path.startswith('/additem'):
            self.additem()
        else:
            self.index()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    """Handle requests in a separate thread."""


try:
    # Create a web server and define the handler to manage the
    # incoming request
    server = ThreadedHTTPServer(('', 8080), myHandler)
    print('Started httpserver')

    # Wait forever for incoming htto requests
    server.serve_forever()
except KeyboardInterrupt:
    pass
