from http.server import HTTPServer, BaseHTTPRequestHandler
import pickle
from os.path import exists
import datetime
from urllib.parse import unquote
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
                0: None,
            },
            f)
    print(
        "Plugin database wasnt found. The one were created, to apply it please restart NTRDB")
    raise SystemExit
with open('html/index.html') as f:
    index = f.read()
with open('html/desc.html') as f:
    desc = f.read()
with open('html/base.html') as f:
    base = f.read()
with open('html/message.html') as f:
    messagehtml = f.read()
with open('html/addfile.html') as f:
    addfile = f.read()
with open('html/links.html') as f:
    links = f.read()
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
        parsed = {}
        for item in data:
            i = item.split("=")
            parsed[i[0]] = unquote(i[1].replace('+', ' '))
    except Exception:
        parsed = {}
    finally:
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

    def description(self):
        parsed = parseURL(self.path)
        if "id" in parsed:
            gid = int(parsed["id"])
            if gid in plugins and not gid == 0:
                item = plugins[gid]
                name = str(item['name'])
                ver = str(item['version'])
                dev = str(item['developer'])
                gamename = str(getgamebytid(item['TitleID']))
                tid = str(item['TitleID'])
                devsite = str(item['devsite'])
                dlink = str(item['plg'])
                descr = str(item['desc'])
                cpb = str(item['compatible'])
                succ = True
        else:
            succ = False
        if succ:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = base % (version,
                           desc % (
                               name, cpb, ver, dev, gamename, tid, devsite, dlink, descr)
                           )
        else:
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = base % (version, messagehtml %
                           ('danger', 'Oops! Looks like you got bad link'))
        self.wfile.write(bytes(page, 'utf-8'))

    def api(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        apidata = {}
        copy = dict(plugins)
        for item in copy:
            if not item == 0:
                plugin = copy[item]
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
                for item in plugins:
                    if not item == 0:
                        num = item
                        plugin = plugins[item]
                        plugin['id'] = num
                        if plugin['TitleID'].startswith(query) or query in plugin['name'] or query in getgamebytid(item["TitleID"]):
                            results.append(plugin)
                for item in results:
                    if not item["TitleID"] == "Not game":
                        name = getgamebytid(item["TitleID"])
                    else:
                        name = ""
                    table = table + links % (
                        name,
                        item["name"],
                        item["compatible"],
                        item["added"],
                        item['plg'],
                        item['devsite'],
                        item['id']
                    )

        if not isSearch:
            for item in plugins:
                if not item == 0:
                    idnum = item
                    item = plugins[item]
                    if not item["TitleID"] == "Not game":
                        name = getgamebytid(item["TitleID"])
                    else:
                        name = ""
                    table = table + links % (
                        name,
                        item["name"],
                        item["compatible"],
                        item["added"],
                        item['plg'],
                        item['devsite'],
                        idnum
                    )
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        page = base % (version, index % (table))
        self.wfile.write(bytes(page, 'utf-8'))

    def additem(self):
        message = ""
        parsed = parseURL(self.path)
        if 'add' in parsed:
            plgp = parsed["link"]
            titleid = parsed['tid']
            plugname = parsed['name']
            developer = parsed['developer']
            devsite = parsed['devsite']
            desc = parsed['desc']
            ver = parsed['ver']
            cpb = parsed['ctype']
            badreq = False
            if plgp == "":
                message = "You havent entered path to plg file!"
                badreq = True
                succ = False
            if titleid == "":
                titleid = "Not game"
            elif not len(titleid) == 16:
                message = "You entered bad TitleID!"
                badreq = True
                succ = False
            if plugname == "":
                message = "You havent entered plugin's name!"
                badreq = True
                succ = False
            if not url(plgp) is True:
                message = "You entered bad plugin download URL!"
                badreq = True
                succ = False
            plgp = plgp
            for item in plugins:
                if not item == 0:
                    plugin = plugins[item]
                    if plugin['plg'] == plgp and plugin['TitleID'] == titleid and plugin['Compatible'] == cpb and plugin['verion'] == ver:
                        badreq = True
                        succ = False
                        message = "Plugin already exists!"
                        break
            if not badreq:
                now = datetime.datetime.now()
                plugins[max(plugins) + 1] = {'TitleID': titleid,
                                             'name': plugname,
                                             'developer': developer,
                                             'devsite': devsite,
                                             'desc': desc,
                                             'plg': plgp,
                                             'added': now.strftime("%Y-%m-%d %H:%M"),
                                             'timestamp': now.timestamp(),
                                             'version': ver,
                                             'compatible': cpb
                                             }
                with open('plugins.pickle', 'wb') as f:
                    pickle.dump(plugins, f)
                message = "Added your plugin!"
                succ = True
            if succ:
                message = messagehtml % ('success', message)
            else:
                message = messagehtml % ('danger', message)
            page = base % (version, message)
        else:
            page = base % (version, addfile)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes(page, 'utf-8'))

    def do_GET(self):
        if self.path.startswith('/api'):
            self.api()
        elif self.path.startswith('/additem'):
            self.additem()
        elif self.path.startswith('/description'):
            self.description()
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
