import smtplib
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from os.path import exists
import datetime
from urllib.parse import unquote
import json
import hashlib
from socketserver import ThreadingMixIn
import threading
from subprocess import check_output
import xml.etree.ElementTree as ET
from html import escape
from uuid import uuid4
from urllib.request import urlopen
from validators import url, email
#import mailsettings
import argparse
from loader import *
import dataset

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int,
                    help='Port for receiving requests', required=False)
args = parser.parse_args()
port = args.port

titles = ET.fromstring(
    str(urlopen('http://3dsdb.com/xml.php').read(), 'utf-8'))
print("3DSDB loaded, optimising it...")
tids = []
for item in titles:
    tids.append([item[1].text, item[8].text])
del titles
print("DONE!")
print("Checking DB for required keys...")

version = str(
    check_output('git log -n 1 --pretty=format:"%h"', shell=True), 'utf-8')
sessions = {}

def computeMD5hash(string):
    m = hashlib.sha512()
    string = str(string)
    m.update(string.encode('utf-8'))
    return m.hexdigest()

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
    db=None
    plugins=None
    users=None
    def __init__(self, *args, **kwargs):
        self.db=dataset.connect("sqlite:///plugs.db") #srry
        self.plugins = self.db.get_table('Plugins')
        self.users = self.db.get_table('Users', primary_id='uuid', primary_type='String(36)')
        super(myHandler, self).__init__(*args, **kwargs)

#######################User zone#################################

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
            page = "<META HTTP-EQUIV=\"refresh\" CONTENT=\"1; URL=index\">"
        else:
            if args is not False:
                if 'email' in args:
                    user = self.users.find_one(email=args["email"])
                    if user!=None:
                        phash = computeMD5hash(args['pword'])
                        if user['activate']:
                            if user['hash'] == phash:
                                page = messagehtml % (
                                    'success', "You succesfully logged in, you will redirect to main page in 5 seconds, or you can click Return To Index<META HTTP-EQUIV=\"refresh\" CONTENT=\"5; URL=index\">")
                                cookie = str(uuid4())
                                sessions[computeMD5hash(cookie)] = args['email']
                            else:
                                page = messagehtml % (
                                    'danger', 'You entered wrong password or email')
                        else:
                            page = messagehtml % (
                                'danger', 'This account hasnt activated yet.')
                    else:
                        page = messagehtml % (
                            'danger', 'You entered wrong password or email')
            else:
                page = login_page
        return page, cookie

    def register(self, parsed):
        if self.checkAuth()[0]:
            return "<META HTTP-EQUIV=\"refresh\" CONTENT=\"1; URL=index\">"
        else:
            if not  parsed:
                return reg_page
            else:
                pwordh = computeMD5hash(parsed['pword'])
                mail = parsed['email']
                del parsed  # FORGET PASSWORD
                if email(mail):
                    if self.users.find_one(email=mail)!=None:
                        if not self.users.find_one(email=mail)['activate']:
                            user=self.users.find_one(email=mail)
                            if self.send_mail(user["email"], user["uuid"]):
                                return messagehtml % (
                                            'info', "Resending the activation mail ntrdb@octonezd.pw!")
                            else:
                                return messagehtml % (
                                            "danger", "failed to reach the mailserver. Please try again later")
                        return messagehtml % (
                            'danger', "This email is already registered")
                    else:
                        tmp = []
                        dmp = json.dumps(tmp)
                        user={'uuid': str(uuid4()), 
                              'email': mail, 
                              'hash' : pwordh, 
                              'plugins': dmp,
                              'activate': False}
                        self.users.insert(user)
                        if self.send_mail(user["email"], user["uuid"]):
                            return messagehtml % (
                                'info', "You almost registered! Now please check your email for activation message from ntrdb@octonezd.pw!")
                        else:
                            return messagehtml% (
                                "danger", "failed to reach the mailserver. Please try again later")
                else:
                    return messagehtml % ('danger', "You entered bad email.")

    def send_mail(self, mail, uid):
        print("Connecting to mail server...")
        try:
            print("Connectin to the mail server")
            mailsrv = smtplib.SMTP(
                host=mailsettings.smtpserver, port=mailsettings.smtpport)
            mailsrv.ehlo()
            mailsrv.starttls()
            print("Logging in...")
            mailsrv.login(mailsettings.user, mailsettings.password)
            print("Logged in!")
        except smtplib.SMTPException as e:
            mailsrv.close()
            return False
        msg = MIMEText(actmsg % (mail, uid))
        msg['Subject'] = 'Confirm activation on NTRDB'
        msg['From'] = mailsettings.user
        msg['To'] = mail
        try:
            mailsrv.send_message(msg)
        except smtplib.SMTPException:
            mailsrv.close()
            return False
        else:
            mailsrv.close()
            return True

    def activate(self):
        args = parseURL(self.path)
        if 'id' in args:
            uid = args['id']
            user=self.users.find_one(uuid=uid)
            if self.users.find_one(uuid=uid)!=None:
                page = messagehtml % (
                    'success', 'You successfully activated account!')
                user['activate'] = True
                self.users.update(user, ['uuid'])
                succ = True
                print(str(self.users.find_one(uuid=uid)))
            else:
                succ=False
        else:
            succ = False
        if succ:
            page = messagehtml % (
                'success', 'You successfully activated account!')
        else:
            page = messagehtml % ('danger', 'Looks like you got bad link :(')
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
            self.wfile.write(bytes((base % (version, '', page + b'<meta http-equiv="refresh" content="1; URL=index">')), 'utf-8'))
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

#######################Plugin managment zone#################################
    def moderator(self):
        table = ""
        isSearch = False
        path = self.path[1:]
        cuser, _ = self.checkAuth()
        if cuser == "admin@ntrdb":
            parsed = parseURL(self.path)
            if not 'allow' in parsed:
                if not isSearch:
                    for item in self.plugins.all():
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
                                item['id'],
                                item['id'],
                                item['id']
                            )
                page = mod % (table)
            else:
                plid = int(parsed['allow'])
                data={"id": plid, "approved": True}
                self.plugins.update(data, ["id"])
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
                elif plugname == "":
                    message = "You havent entered plugin's name!"
                    badreq = True
                    succ = False
                elif not url(plgp) or not url(pic) or not url(devsite):
                    message = "You entered bad URL!"
                    badreq = True
                    succ = False
                if self.plugins.find_one(plg=plgp, TitleID=titleid, compatible=cpb, version= ver) != None:
                        badreq = True
                        succ = False
                        message = "Plugin already exists!"
                if not badreq:
                    now = datetime.datetime.now()
                    if cuser == 'admin@ntrdb':
                        approved = True
                    else:
                        approved = False
                    plgid = self.plugins.insert({'TitleID': titleid,
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
                                     'approved': approved,
                                     'uploader': cuser
                                     })
                    tmp = self.users.find_one(email=cuser)
                    tmp = self.updPlgArr(tmp, plgid)
                    self.users.update(tmp, ['email'])
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

    def updPlgArr(self, user, newPlg):
        arr=user['plugins']
        arr = json.loads(arr)
        arr.append(newPlg)
        dmp = json.dumps(arr)
        user['plugins'] = dmp
        return user


    def manage(self):
        cuser, _ = self.checkAuth()
        if cuser:
            uplg = []
            table = ''
            user= None
            if cuser == "admin@ntrdb":
                plglist=self.plugins.all()
                for item in plglist:
                    uplg.append(item['id'])
            else:
                user=self.users.find_one(email=cuser)
                plglist = json.loads(user['plugins'])
                for item in plglist:
                    if self.plugins.find_one(id=item):
                        uplg.append(item)
            for item in uplg:
                plugin = self.plugins.find_one(id=item)
                table = table + \
                    links_mng % (plugin['name'], plugin['added'], item, item)
            return managepage % table
        else:
            return messagehtml % ('danger', 'You cant manage your plugins because you are not logged in')


    def edit(self):
        args = parseURL(self.path)
        plid = int(args['plugid'])
        cuser = self.checkAuth()[0]
        if cuser:
            if plid in json.loads(self.users.find_one(email=cuser)['plugins']) or cuser == 'admin@ntrdb':
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
                    for plugin in self.plugins.all():
                        if plugin['plg'] == plgp and plugin['TitleID'] == titleid and plugin['compatible'] == cpb and plugin['version'] == ver and plid!=plugin["id"]:
                            badreq = True
                            succ = False
                            message = "Plugin already exists!"
                            break
                    if not badreq:
                        now = datetime.datetime.now()
                        plugin = {'TitleID': titleid,
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
                                         'id': plid
                                         }
                        self.plugins.update(plugin, ["id"])
                        message = "Your plugin was edited successfully"
                        succ = True
                    if succ:
                        message = messagehtml % ('success', message)
                    else:
                        message = messagehtml % ('danger', message)
                    page = message
                else:
                    pl = self.plugins.find_one(id=plid)
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

    def rm(self):
        cuser, _ = self.checkAuth()
        args = parseURL(self.path)
        if cuser:
            plugid = int(args['plugid'])
            if self.plugins.find_one(id=plugid)!=None:
                if plugid in json.loads(self.users.find_one(email=cuser)['plugins']) or cuser == 'admin@ntrdb':
                    if 'sure' not in args:
                        plugin = self.plugins.find_one(id=plugid)
                        pg = removal % (
                            plugid,
                            plugin['name'],
                            plugin['name'])
                        return pg
                    else:
                        plugin = self.plugins.find_one(id=plugid)
                        user = self.users.find_one(email=plugin['uploader'])
                        print(str(user))
                        user['plugins'] = json.loads(user['plugins'])
                        del user['plugins'][user['plugins'].index(plugid)]
                        user['plugins'] = json.dumps(user['plugins'])
                        self.users.update(user, ['email'])
                        self.plugins.delete(id=plugid)
                        return messagehtml % ('success', 'Your plugin was removed')
                else:
                    return messagehtml % ('danger', 'You are not the one who added this plugin!')
            else:
                return messagehtml % ('warning', 'No plugin with that ID found.')

###########################info zone##########################################

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
                for plugin in self.plugins.all():
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
            for item in self.plugins.all():
                idnum = item["id"]
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


    def description(self):
        parsed = parseURL(self.path)
        if "id" in parsed:
            gid = int(parsed["id"])
            cuser, _ = self.checkAuth()
            try:
                if cuser == 'admin@ntrdb' or gid in self.users.all():
                    options = 'Options:<a href="edit?plugid=%s" class="btn btn-secondary btn-sm">Edit</a><a href="rm?plugid=%s" class="btn btn-danger btn-sm">Remove</a>' % (
                            parsed['id'], parsed['id'])
                else:
                    options = ''
            except KeyError:
                options = ''
            if self.plugins.find(id=gid) != None:
                item = self.plugins.find_one(id=gid)
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
                    pic = "<p>Screenshot:</p><img src=\"%s\" class=\"screenshot\">" % (
                        str(item['pic']))
                else:
                    pic = ""
                succ = True
        else:
            succ = False
        if succ:
            page = desc % (name, cpb, ver, dev, gamename, tid, devsite, dlink, descr, pic, options)
        else:
            page = messagehtml % (
                'danger', 'Oops! Looks like you got bad link')
        return page


    def api(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        apidata = {}
        copy = self.plugins.all()
        for item in copy:
            if item['approved']:
                del item["uploader"]
                del item["approved"]
                apidata[item['id']] = item
        self.wfile.write(bytes(json.dumps(apidata), 'utf-8'))

###########################httplib zone########################################

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

db = dataset.connect("sqlite:///plugs.db")
tmp = db.get_table('Users', primary_id='uuid', primary_type='String(36)')
if tmp.find_one(email="admin@ntrdb")==None:
    psswd = input("Set the admins password: ")
    h = computeMD5hash(psswd)
    del psswd
    tmp.insert({'uuid': "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 'email': "admin@ntrdb", 'hash' : h, 'plugins': "[]",'activate': True})

try:
    if port:
        server = ThreadedHTTPServer(('', port), myHandler)
    else:
        server = ThreadedHTTPServer(('', 4443), myHandler)

    print('Started httpserver')

    # Wait forever for incoming http requests
    server.serve_forever()
except KeyboardInterrupt:
    pass
