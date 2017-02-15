from http.server import HTTPServer, BaseHTTPRequestHandler
import pickle
from os.path import exists
import datetime
from urllib.parse import unquote
from uuid import uuid4
from json import dumps
import hashlib
from validators import url
global plugins
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


def computeMD5hash(string):
    m = hashlib.md5()
    m.update(string.encode('utf-8'))
    return m.hexdigest()


class myHandler(BaseHTTPRequestHandler):

    def api(self):
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()
        apidata = {}
        for item in plugins['ids']:
            if not item == 0:
                plugin = plugins['ids'][item]
                apidata[item] = plugin
                del apidata[item]["__removal_id"]

        self.wfile.write(bytes(dumps(apidata), 'utf-8'))

    def user(self):
        table = ""
        message = ""
        isSearch = False
        addfile = """
        <form method="get">
        <p>Enter a URL to .plg file: <input type="text" name="plg" autocomplete="off"></p>
        <p>Enter title ID of the game: <input type="text" name="titid" autocomplete="off"></p>
        <p>Enter name of the plugin: <input type="text" name="name" autocomplete="off"></p>
        <input type="submit" value="Submit NTR Plugin">
        </form>"""
        search = """
        <form method="get">
        <p width=100%%><input type="text" name="search" autocomplete="off"><input type="submit" value="Search!"></p>
        </form>
        """
        remove = """
        <form method="get">
        <p>Enter a Removal ID: <input type="text" name="rid" autocomplete="off"></p>
        <input type="submit" value="Remove your plugin">
        </form>"""
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
                                                               'name': plugname,
                                                               'plg': unquote(plgp),
                                                               'added': now.strftime("%Y-%m-%d %H:%M"),
                                                               'timestamp': now.timestamp(),
                                                               '__removal_id': computeMD5hash(removal_id)
                                                               }
                    with open('plugins.pickle', 'wb') as f:
                        pickle.dump(plugins, f)
                    message = "Added your plugin! Removal ID is:{}. Store it somewhere;It used to remove plugin".format(
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
            page = """
            <html>
            <head>
            <link href="https://fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet">
            <style>
            body {
                font-family: 'Open Sans', sans-serif;
            }
            </style>
            </head>
            <body>
            <a href="https://github.com/OctoNezd/NTRDB"><img style="position: absolute; top: 0; right: 0; border: 0;" src="https://camo.githubusercontent.com/38ef81f8aca64bb9a64448d0d70f1308ef5341ab/68747470733a2f2f73332e616d617a6f6e6177732e636f6d2f6769746875622f726962626f6e732f666f726b6d655f72696768745f6461726b626c75655f3132313632312e706e67" alt="Fork me on GitHub" data-canonical-src="https://s3.amazonaws.com/github/ribbons/forkme_right_darkblue_121621.png"></a>
            <h1>NTR plugins database</h1>
            <hr>
            <table width=100%%>
            <tr>
            <td>
            <h3>Submit your NTR Plugin!</h3>
            %s
            </td>
            <td>
            <h3>Remove your NTR Plugin</h3>
            %s
            </td>
            </tr>
            </table>
            <hr>
            %s
            <table table border="1" cellpadding="5" cellspacing="5" width=100%%>
            <tr>
            <th>Game's TitleID</th>
            <th>Plugins name</th>
            <th>Added</th>
            <th>Download</th>
            </tr>
            %s
            </table>
            </body>
            </html
            """ % (addfile, remove, search, table)
        else:
            if succ:
                color = 'green'
            else:
                color = 'red'
            page = """
            <html>
            <head>
            <link href="https://fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet">
            <style>
            body {
                font-family: 'Open Sans', sans-serif;
                margin-top: 0;
                margin-left: 25%%;
                margin-right: 25%%;
            }
            div {
                background-color: #f7f7f7;
                border: 2px solid;
                border-radius: 10px;
                border-top-left-radius: 0;
                border-top-right-radius: 0;
                border-top: 6px solid %s;
                border-bottom: 2px solid;
            }
            </style>
            </head>
            <body>
            <center>
            <div><h2>
            %s
            </h2>
            <a href="/index.html">Return to main page</a>
            </div>
            </center>
            </body>
            </html>
            """ % (color, message)
        self.wfile.write(bytes(page, 'utf-8'))

    # Handler for the GET requests
    def do_GET(self):
        if not self.path.startswith('/api'):
            self.user()
        else:
            self.api()


try:
    # Create a web server and define the handler to manage the
    # incoming request
    server = HTTPServer(('', 8080), myHandler)
    print('Started httpserver')

    # Wait forever for incoming htto requests
    server.serve_forever()
except KeyboardInterrupt:
    pass
