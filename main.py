import smtplib
from email.mime.text import MIMEText
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
from html import escape
from uuid import uuid4
from urllib.request import urlopen
from validators import url, email
import mailsettings
import argparse
from loader import *
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int,
                    help='Port for receiving requests', required=False)
args = parser.parse_args()
port = args.port


def computeMD5hash(string):
    m = hashlib.sha512()
    string = str(string)
    m.update(string.encode('utf-8'))
    return m.hexdigest()


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
if exists('users.pickle'):
    with open('users.pickle', 'rb') as f:
        users = pickle.load(f)
else:
    print(
        'Looks like you are running NTRDB first time or you removed users.pickle file.')
    print('Please set admin password.')
    pword = computeMD5hash(input())
    with open('users.pickle', 'wb') as f:
        pickle.dump(
            {
                'admin@ntrdb': [pword, True, []],
            },
            f)
    print(
        "Please restart NTRDB to apply changes")
    raise SystemExit

titles = ET.fromstring(
    str(urlopen('http://3dsdb.com/xml.php').read(), 'utf-8'))
print("3DSDB loaded, optimising it...")
tids = []
for item in titles:
    tids.append([item[1].text, item[8].text])
del titles
print("DONE!")
print("Checking DB for required keys...")
for item in plugins:
    if not item == 0:
        if not 'pic' in plugins[item]:
            plugins[item]['pic'] = ""
        plugins[item]['TitleID'] = plugins[item]['TitleID'].upper()
with open('plugins.pickle', 'wb') as f:
    pickle.dump(plugins, f)
version = str(
    check_output('git log -n 1 --pretty=format:"%h"', shell=True), 'utf-8')
print("Connecting to mail server...")
try:
    mailsrv = smtplib.SMTP_SSL(
        host=mailsettings.smtpserver, port=mailsettings.smtpport)
    print("Logging in...")
    mailsrv.login(mailsettings.user, mailsettings.password)
    print("Logged in!")
except smtplib.SMTPException as e:
    print("There was an error connecting to mail server!")
    raise e
    raise SystemExit
sessions = {}


def parsePost(string):
    tmp = string.split('&')
    parsed = {}
    for item in tmp:
        temp = item.split('=')
        parsed[unquote(temp[0])] = unquote(temp[1])
    return parsed


def parseURL(path):
    try:
        data = path.split("?")[1].split("&")
        parsed = {}
        for item in data:
            i = item.split("=")
            parsed[i[0]] = escape(unquote(i[1].replace('+', ' ')))
    except Exception:
        parsed = {}
    finally:
        return parsed


def parseCookie(header):
    if 'Cookie' in header:
        cookies_raw = header["Cookie"].split('; ')
        cookies = {}
        for item in cookies_raw:
            cookie = item.split('=')
            cookies[cookie[0]] = cookie[1].replace('"', '')
        return cookies
    else:
        return {}


def getgamebytid(tid):
    ok = False
    for item in tids:
        if item[1] == tid:
            return item[0]
            ok = True
    if not ok:
        return "Game TitleID hasnt found in 3DSDB :("


class myHandler(BaseHTTPRequestHandler):

    def checkAuth(self):
        """Returns user email and speccall"""
        if len(self.cookie) > 0:
            if 'AToken' in self.cookie:
                if computeMD5hash(self.cookie['AToken']) in sessions:
                    return sessions[computeMD5hash(self.cookie['AToken'])], False
                else:
                    # If user have bad cookie
                    self.send_response(200)
                    self.send_header('Set-Cookie', 'AToken=%s;HttpOnly;%s' %
                                     (self.cookie['AToken'], 'Expires=Wed, 21 Oct 2007 07:28:00 GMT'))
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(
                        b'Please wait...<meta http-equiv="refresh" content="1">')
                    return False, True
            else:
                return False, False
        else:
            return False, False

    def ulogpage(self, args):
        cookie = None
        cuser, _ = self.checkAuth()
        if cuser:
            print()
            page = "<META HTTP-EQUIV=\"refresh\" CONTENT=\"1; URL=index\">"
        else:
            if args is not False:
                if 'email' in args:
                    if args['email'] in users:
                        user = users[args['email']]
                        phash = computeMD5hash(args['pword'])
                        # print(user)
                        # print(phash)
                        if user[1] is True:
                            if user[0] == phash:
                                page = messagehtml % (
                                    'success', "You succesfully logged in, you will redirect to main page in 5 seconds, or you can click Return To Index<META HTTP-EQUIV=\"refresh\" CONTENT=\"5; URL=index\">")
                                cookie = str(uuid4())
                                sessions[
                                    computeMD5hash(cookie)] = args['email']
                            else:
                                page = messagehtml % (
                                    'danger', 'You entered wrong password or email')
                        else:
                            page = messagehtml % (
                                'danger', 'This account hasnt activated yet.')
                            # print(page)
                    else:
                        page = messagehtml % (
                            'danger', 'You entered wrong password or email')
            else:
                page = login_page
        return page, cookie

    def activate(self):
        args = parseURL(self.path)
        if 'id' in args:
            uid = args['id']
            for user in users:
                user = users[user]
                if user[1] == uid:
                    page = messagehtml % (
                        'success', 'You successfully activated account!')
                    user[1] = True
                    user.append([])
                    succ = True
                    with open('users.pickle', 'wb') as f:
                        pickle.dump(users, f)
                    break
        else:
            succ = False
        if succ:
            page = messagehtml % (
                'success', 'You successfully activated account!')
        else:
            page = messagehtml % ('danger', 'Looks like you got bad link :(')
        return page

    def description(self):
        parsed = parseURL(self.path)
        if "id" in parsed:
            gid = int(parsed["id"])
            cuser, _ = self.checkAuth()
            try:
                if cuser == 'admin@ntrdb' or gid in users[cuser][2]:
                    options = 'Options:<a href="edit?plugid=%s" class="btn btn-secondary btn-sm">Edit</a><a href="rm?plugid=%s" class="btn btn-danger btn-sm">Remove</a>' % (
                            parsed['id'], parsed['id'])
                else:
                    options = ''
            except KeyError:
                options = ''
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
                if not str(item['pic']) == "":
                    pic = "<p>Screenshot:</p><img src=\"%s\">" % (
                        str(item['pic']))
                else:
                    pic = ""
                succ = True
        else:
            succ = False
        if succ:
            page = desc % (
                name, cpb, ver, dev, gamename, tid, devsite, dlink, descr, pic, options)
        else:
            page = messagehtml % (
                'danger', 'Oops! Looks like you got bad link')
        return page

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
        isSearch = False
        path = self.path[1:]
        if not len(path.split("?")) == 1:
            parsed = parseURL(self.path)
            if 'search' in parsed:
                query = str(parsed['search'])
                isSearch = True
                results = []
                for item in plugins:
                    if not item == 0:
                        num = item
                        plugin = plugins[item]
                        plugin['id'] = num
                        if str(plugin['TitleID']).startswith(query) or query.upper() in str(plugin['name']).upper() or query.upper() in str(getgamebytid(plugin["TitleID"])).upper():
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
                    if item['approved'] == True:
                        table = table + links % (
                            name,
                            item["name"],
                            item["compatible"],
                            item["added"],
                            item['plg'],
                            item['devsite'],
                            idnum
                        )
        page = index % (table)
        return page


    def moderator(self):
        table = ""
        isSearch = False
        path = self.path[1:]
        cuser, _ = self.checkAuth()
        if cuser == "admin@ntrdb":
            parsed = parseURL(self.path)
            if not 'allow' in parsed:
                if not isSearch:
                    for item in plugins:
                        if not item == 0:
                            idnum = item
                            item = plugins[item]
                            if not item["TitleID"] == "Not game":
                                name = getgamebytid(item["TitleID"])
                            else:
                                name = ""
                            if item['approved'] is False:
                                table = table + links_mod % (
                                    name,
                                    item["name"],
                                    item["compatible"],
                                    item["added"],
                                    item['plg'],
                                    item['devsite'],
                                    idnum,
                                    idnum,
                                    idnum
                                )
                page = mod % (table)
            else:
                plid = int(parsed['allow'])
                plugins[plid]['approved'] = True
                with open('plugins.pickle', 'wb') as f:
                    pickle.dump(plugins, f)
                page = messagehtml % ('success','Plugin was approved!')
        else:
            page = messagehtml % ('info', 'This page avaible only for admin')
        return page

    def additem(self):
        cuser = self.checkAuth()[0]
        if cuser:
            message = ""
            parsed = parseURL(self.path)
            if 'add' in parsed:
                plgp = parsed["link"]
                titleid = parsed['tid'].upper()
                plugname = parsed['name']
                developer = parsed['developer']
                devsite = parsed['devsite']
                desc = parsed['desc']
                ver = parsed['ver']
                cpb = parsed['ctype']
                pic = parsed['pic']
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
                if not url(plgp) or not url(pic) or not url(devsite):
                    message = "You entered bad URL!"
                    badreq = True
                    succ = False
                for item in plugins:
                    if not item == 0:
                        plugin = plugins[item]
                        if plugin['plg'] == plgp and plugin['TitleID'] == titleid and plugin['compatible'] == cpb and plugin['verion'] == ver:
                            badreq = True
                            succ = False
                            message = "Plugin already exists!"
                            break
                if not badreq:
                    now = datetime.datetime.now()
                    plid = max(plugins) + 1
                    if cuser == 'admin@ntrdb':
                        approved = True
                    else:
                        approved = False
                    plugins[plid] = {'TitleID': titleid,
                                     'name': plugname,
                                     'developer': developer,
                                     'devsite': devsite,
                                     'desc': desc,
                                     'plg': plgp,
                                     'added': now.strftime("%Y-%m-%d %H:%M"),
                                     'timestamp': now.timestamp(),
                                     'version': ver,
                                     'compatible': cpb,
                                     'pic': pic,
                                     'approved': approved
                                     }
                    users[cuser][2].append(plid)
                    with open('plugins.pickle', 'wb') as f:
                        pickle.dump(plugins, f)
                    with open('users.pickle', 'wb') as f:
                        pickle.dump(users, f)
                    message = "Your plugin were added to base. Now you need to wait for moderator to approve it."
                    succ = True
                if succ:
                    message = messagehtml % ('success', message)
                else:
                    message = messagehtml % ('danger', message)
                page = message
            else:
                page = addfile
        else:
            page = messagehtml % (
                'danger', 'You cant add items because you are not logged in.')
        return page

    def edit(self):
        args = parseURL(self.path)
        plid = int(args['plugid'])
        cuser = self.checkAuth()[0]
        if cuser:
            if plid in users[cuser][2] or cuser == 'admin@ntrdb':
                message = ""
                if 'edit' in args:
                    plgp = args["link"]
                    titleid = args['tid'].upper()
                    plugname = args['name']
                    developer = args['developer']
                    devsite = args['devsite']
                    desc = args['desc']
                    ver = args['ver']
                    cpb = args['ctype']
                    pic = args['pic']
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
                    if not url(plgp) or not url(pic) or not url(devsite):
                        message = "You entered bad URL!"
                        badreq = True
                        succ = False
                    for item in plugins:
                        if not item == 0:
                            plugin = plugins[item]
                            if plugin['plg'] == plgp and plugin['TitleID'] == titleid and plugin['compatible'] == cpb and plugin['verion'] == ver:
                                badreq = True
                                succ = False
                                message = "Plugin already exists!"
                                break
                    if not badreq:
                        now = datetime.datetime.now()
                        plugins[plid] = {'TitleID': titleid,
                                         'name': plugname,
                                         'developer': developer,
                                         'devsite': devsite,
                                         'desc': desc,
                                         'plg': plgp,
                                         'added': now.strftime("%Y-%m-%d %H:%M"),
                                         'timestamp': now.timestamp(),
                                         'version': ver,
                                         'compatible': cpb,
                                         'pic': pic
                                         }
                        with open('plugins.pickle', 'wb') as f:
                            pickle.dump(plugins, f)
                        message = "Your plugin was edited successfully"
                        succ = True
                    if succ:
                        message = messagehtml % ('success', message)
                    else:
                        message = messagehtml % ('danger', message)
                    page = message
                else:
                    pl = plugins[plid]
                    page = editpage % (
                        plid,
                        pl['name'],
                        pl['desc'],
                        pl['version'],
                        pl['developer'],
                        pl['TitleID'],
                        pl['devsite'],
                        pl['plg'],
                        pl['pic']
                    )
            else:
                page = messagehtml % (
                    'danger', 'You cant add items because you are not logged in.')
        return page

    def register(self, parsed):
        if self.checkAuth()[0]:
            page = "<META HTTP-EQUIV=\"refresh\" CONTENT=\"1; URL=index\">"
        else:
            if parsed == False:
                page = reg_page
            else:
                pwordh = computeMD5hash(parsed['pword'])
                mail = parsed['email']
                del parsed  # FORGET PASSWORD
                if email(mail):
                    if mail in users:
                        page = messagehtml % (
                            'danger', "This email is already registered")
                    else:
                        users[mail] = [pwordh, str(uuid4())]
                        msg = MIMEText(actmsg % (mail, users[mail][1]))
                        msg['Subject'] = 'Confirm activation on NTRDB'
                        msg['From'] = mailsettings.user
                        msg['To'] = mail
                        while 1:
                            try:
                                mailsrv.send_message(msg)
                            except smtplib.SMTPException:
                                pass
                            else:
                                break
                        page = messagehtml % (
                            'info', "You almost registered! Now please check your email for activation message from ntrdb@octonezd.pw!")
                else:
                    page = messagehtml % ('danger', "You entered bad email.")
            return page

    def logout(self):
        cuser = self.checkAuth()[0]
        if cuser:
            self.send_response(200)
            self.send_header('Set-Cookie', 'AToken=%s;HttpOnly;%s' %
                             (self.cookie['AToken'], 'Expires=Wed, 21 Oct 2007 07:28:00 GMT'))
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = bytes(messagehtml % ('success', 'You logged out'), 'utf-8')
            self.wfile.write(base % (version, '', page +
                                     b'<meta http-equiv="refresh" content="1; URL=index">'))
            del sessions[computeMD5hash(self.cookie['AToken'])]
        else:
            page = base % (version, '', messagehtml % ('danger', "<center><figure class=\"figure\">"
                                                       "<img src=\"http://share.mostmodest.ru/2017/02/H2hgPCa.png\" class=\"figure-img img-fluid rounded\" alt=\"meme\">"
                                                       "<figcaption class=\"figure-caption\">You cant logout if you are not logged in.</figcaption>"
                                                       "</figure></center>"))
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(page, 'utf-8'))
        return

    def manage(self):
        cuser, _ = self.checkAuth()
        if cuser:
            uplg = []
            table = ''
            for item in users[cuser][2]:
                if item in plugins:
                    uplg.append(item)
            for item in uplg:
                plugin = plugins[item]
                table = table + \
                    links_mng % (plugin['name'], plugin['added'], item, item)
            return managepage % table
        else:
            return messagehtml % ('danger', 'You cant manage your plugins because you are not logged in')

    def rm(self):
        cuser, _ = self.checkAuth()
        args = parseURL(self.path)
        if cuser:
            plugid = int(args['plugid'])
            if plugid in plugins:
                if plugid in users[cuser][2] or cuser == 'admin@ntrdb':
                    if 'sure' not in args:
                        pg = removal % (
                            plugid,
                            plugins[plugid]['name'],
                            plugins[plugid]['name'])
                        return pg
                    else:
                        del plugins[plugid]
                        try:
                            users[cuser][2].pop(users[cuser][2].index(plugid))
                        except Exception:
                            pass
                        with open('plugins.pickle', 'wb') as f:
                            pickle.dump(plugins, f)
                        with open('users.pickle', 'wb') as f:
                            pickle.dump(users, f)
                        return messagehtml % ('success', 'Your plugin was removed')
                else:
                    return messagehtml % ('danger', 'You are not the one who added this plugin!')
            else:
                return messagehtml % ('warning', 'No plugin with that ID found.')

    def do_GET(self):
        speccall = False
        self.cookie = parseCookie(dict(self.headers))
        # print(sessions)
        # print(self.cookie)
        cuser, rcookies = self.checkAuth()
        if cuser:
            if cuser == 'admin@ntrdb':
                nbar = nbar_loggedin % (cuser, '<a class="dropdown-item" href="mod">Moderation</a>')
            else:
                nbar = nbar_loggedin % (cuser, '')
        else:
            nbar = nbar_login
        if not rcookies:
            try:
                if self.path.startswith('/api'):
                    speccall = True
                    self.api()
                elif self.path.startswith('/additem'):
                    page = self.additem()
                elif self.path.startswith('/description'):
                    page = self.description()
                elif self.path.startswith('/reg'):
                    page = self.register(False)
                elif self.path.startswith('/activate'):
                    page = self.activate()
                elif self.path.startswith('/login'):
                    lpage = self.ulogpage(False)
                    page = lpage[0]
                elif self.path.startswith('/manage'):
                    page = self.manage()
                elif self.path.startswith('/mod'):
                    page = self.moderator()
                elif self.path.startswith('/logout'):
                    page = self.logout()
                    speccall = True
                elif self.path.startswith('/edit'):
                    page = self.edit()
                elif self.path.startswith('/favicon'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'image/png')
                    self.end_headers()
                    self.wfile.write(icon)
                elif self.path.startswith('/error'):
                    1 / 0
                elif self.path.startswith('/rm'):
                    page = self.rm()
                else:
                    page = self.index()
                if not speccall:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    page = base % (version, nbar, page)
                    self.wfile.write(bytes(page, 'utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (version, nbar, messagehtml %
                               ('danger', 'Oops! An error occured when processing your request!'))
                self.wfile.write(bytes(page, 'utf-8'))
                raise e

    def do_POST(self):
        self.cookie = parseCookie(dict(self.headers))
        # Doesn't do anything with posted data
        try:
            # <--- Gets the size of data
            content_length = int(self.headers['Content-Length'])
            # <--- Gets the data itself
            post_data = self.rfile.read(content_length)
            pdata = parsePost(str(post_data, 'utf-8'))
            if 'rtype' in pdata:
                scookie = False
                if pdata['rtype'] == 'loginpg':
                    page, cookie = self.ulogpage(pdata)
                    scookie = True
                elif pdata['rtype'] == 'regpg':
                    page = self.register(pdata)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                if scookie:
                    # print(scookie)
                    # print(cookie)
                    self.send_header('Set-Cookie', 'AToken=%s' % (cookie))
                self.end_headers()
                self.wfile.write(bytes(base % (version, "", page), 'utf-8'))
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(
                    bytes(base % (version, "", messagehtml % ('danger', 'Bad request!'))), 'utf-8')
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = base % (version, "", messagehtml %
                           ('danger', 'Oops! An error occured when processing your request!'))
            self.wfile.write(bytes(page, 'utf-8'))
            raise e


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    """Handle requests in a separate thread."""


try:
    if port:
        server = ThreadedHTTPServer(('', port), myHandler)
    else:
        server = ThreadedHTTPServer(('', 8080), myHandler)
    print('Started httpserver')

    # Wait forever for incoming http requests
    server.serve_forever()
except KeyboardInterrupt:
    pass
