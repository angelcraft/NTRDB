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
from validators import url
global plugins, index, messagehtml
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
with open('html/message.html') as f:
    messagehtml = f.read()
with open('html/search.html') as f:
    search = f.read()
with open('html/addfile.html') as f:
    addfile = f.read()
with open('html/remove.html') as f:
    remove = f.read()


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
        print(plugins)
        print(copy)
        for item in copy['ids']:
            if not item == 0:
                plugin = copy['ids'][item]
                apidata[item] = plugin
        print(plugins)
        print(copy)
        self.wfile.write(bytes(dumps(apidata), 'utf-8'))

    def user(self):
        table = ""
        message = ""
        isSearch = False
        path = self.path[1:]
        if not len(path.split("?")) == 1:
            data = path.split("?")[1].split("&")
            parsed = {}
            for item in data:
                i = item.split("=")
                parsed[i[0]] = i[1]
            if 'plg' in parsed:
                plgp = parsed["plg"]
                titleid = parsed['titid']
                plugname = parsed['name']
                badreq = False
                if plgp == "":
                    message = "You havent entered path to plg file!"
                    badreq = True
                    succ = False
                if titleid == "":
                    message = "You havent entered game's TitleID!"
                    badreq = True
                    succ = False
                if plugname == "":
                    message = "You havent entered plugin's name!"
                    badreq = True
                    succ = False
                elif not len(titleid) == 16:
                    message = "You entered bad TitleID!"
                    badreq = True
                    succ = False
                if not url(unquote(plgp)) == True:
                    message = "You entered bad URL!"
                    badreq = True
                    succ = False
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
                    plugins['ids'][max(plugins['ids']) + 1] = {'TitleID': titleid,
                                                               'name': plugname.replace('+', ' '),
                                                               'plg': unquote(plgp),
                                                               'added': now.strftime("%Y-%m-%d %H:%M"),
                                                               'timestamp': now.timestamp(),
                                                               }
                    with open('plugins.pickle', 'wb') as f:
                        pickle.dump(plugins, f)
                    message = "Added your plugin!".format(
                        removal_id) + message
                    succ = True
            if 'gid' in parsed:
                searchq = parsed['gid']
                if searchq == "":
                    message = "You havent entered game's TitleID!" + message
                    succ = False
            if 'plugname' in parsed:
                searchq = parsed['plugname']
                if searchq == "":
                    message = "You havent entered plugin's name!" + message
                    succ = False
                else:
                    isSearch = True
            """
            if 'rid' in parsed:
                rid = computeMD5hash(parsed['rid'])
                succ = False
                for item in plugins['ids']:
                    if not item == 0:
                        if plugins['ids'][item]['__removal_id'] == rid:
                            del plugins['ids'][item]
                            message = "Your plugin has been removed..."
                            succ = True
                            with open('plugins.pickle', 'wb') as f:
                                pickle.dump(plugins, f)
                            break
                if not succ:
                    message = "No plugin which matches this removal ID found"
                    succ = False
            """
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
                    table = table + "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href=\"%s\">Download</a></td></tr>" % (
                        item["TitleID"],
                        item["name"],
                        item["added"],
                        item['plg']
                    )

        if not isSearch:
            for item in plugins['ids']:
                if not item == 0:
                    item = plugins['ids'][item]
                    table = table + "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href=\"%s\">Download</a></td></tr>" % (
                        item["TitleID"],
                        item["name"],
                        item["added"],
                        item['plg']
                    )
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        # Send the html message
        if message == "":
            page = index % (addfile, remove, search, table)
        else:
            if succ:
                color = 'green'
            else:
                color = 'red'
            page = messagehtml % (color, message)
        self.wfile.write(bytes(page, 'utf-8'))

    # Handler for the GET requests
    def do_GET(self):
        if not self.path.startswith('/api'):
            self.user()
        else:
            self.api()


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
