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
from time import time
import argparse
from loader import *
import dataset
from custom_exception import MissingPermission, SQLException
import database

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
    cdb = None

    def __init__(self, *args, **kwargs):
        self.cdb = database.database()
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
                    user = self.cdb.getUser(email=args['email'])
                    if user != None:
                        phash = computeMD5hash(args['pword'])
                        if user['activate']:
                            if user['hash'] == phash:
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
            if not parsed:
                return reg_page
            else:
                mail = parsed['email']
                if email(mail):
                    search = self.cdb.getUser(email=mail)
                    if search != None:
                        """
                        if not search['activate']:
                            if self.send_mail(search["email"], search["uuid"]):
                                return messagehtml % (
                                    'info', "Resending the activation mail from ntrdb@octonezd.pw!")
                            else:
                                return messagehtml % (
                                    "danger", "Failed to reach the mailserver. Please try again later")
                        return messagehtml % (
                            'danger', "This email is already registered")
                        """
                    else:
                        user = self.cdb.addUser(mail, parsed['pword'])
                        self.cdb.activateUser(uid=user['uuid'])
                        if self.send_mail(user["email"], user["uuid"]):
                            return messagehtml % (
                                'info', "You have registered succesfully!")
                        else:
                            return messagehtml % (
                                "danger", "Failed to reach the mailserver. Please try again later")
                else:
                    return messagehtml % ('danger', "You entered bad email.")

    def send_mail(self, mail, uid):
        return True
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
            if self.cdb.activateUser(uid=uid):
                succ = True
            else:
                succ = False
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
            self.wfile.write(bytes((base % (
                version, page + b'<meta http-equiv="refresh" content="1; URL=index">', '', str(1))), 'utf-8'))
            del sessions[computeMD5hash(self.cookie['AToken'])]
        else:
            page = base % (version, '', messagehtml % ('danger', "<center><figure class=\"figure\">"
                                                       "<img src=\"http://share.mostmodest.ru/2017/02/H2hgPCa.png\" class=\"figure-img img-fluid rounded\" alt=\"meme\">"
                                                       "<figcaption class=\"figure-caption\">You cant logout if you are not logged in.</figcaption>"
                                                       "</figure></center>"), '')
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
        luser = self.cdb.getUser(email=cuser)
        if luser["permissions"] <= database.MOD_LEVEL:
            parsed = parseURL(self.path)
            if not 'allow' in parsed:
                if not isSearch:
                    for item in self.cdb.getModPlugins():
                        if not item["TitleID"] == "Not game":
                            name = getgamebytid(item["TitleID"])
                        else:
                            name = ""
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
                self.cdb.allowPlugin(cuser, plid)
                page = messagehtml % ('success', 'Plugin was approved!')
        else:
            page = messagehtml % ('info', 'This page avaible only for admin')
        return page

    def additem(self):
        cuser = self.checkAuth()[0]
        luser = self.cdb.getUser(email=cuser)
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
                if self.cdb.getCloned(plg=plgp, TitleID=titleid, compatible=cpb, version=ver):
                    badreq = True
                    succ = False
                    message = "Plugin already exists!"
                if not badreq:
                    now = datetime.datetime.now()
                    plugin = self.cdb.addPlugin(
                        cuser, plugname, desc, ver, developer, titleid, devsite, plgp, cpb, pic)
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

    def manage(self):
        cuser, _ = self.checkAuth()
        luser = self.cdb.getUser(email=cuser)
        if cuser:
            uplg = []
            table = ''
            user = None
            if luser['permissions'] <= database.ADMIN_LEVEL:
                plglist = self.cdb.getAllPlugins()
                for item in plglist:
                    uplg.append(item['id'])
            else:
                user = self.cdb.getUser(email=cuser)
                for item in user['plugins']:
                    if self.cdb.getPlugin(pid=item):
                        uplg.append(item)
            for item in uplg:
                plugin = self.cdb.getPlugin(pid=item)
                table = table + \
                    links_mng % (plugin['name'], plugin['added'], item, item)
            return managepage % table
        else:
            return messagehtml % ('danger', 'You cant manage your plugins because you are not logged in')

    def edit(self):
        args = parseURL(self.path)
        plid = int(args['plugid'])
        cuser = self.checkAuth()[0]
        luser = self.cdb.getUser(email=cuser)
        if cuser:
            if plid in luser['plugins'] or luser['permissions'] <= database.ADMIN_LEVEL:
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
                    cl = self.cdb.getCloned(
                        plg=plgp, TitleID=titleid, compatible=cpb, version=ver)
                    if cl and cl["id"] != plid:
                        badreq = True
                        succ = False
                        message = "Plugin already exists!"
                    if not badreq:
                        now = datetime.datetime.now()
                        plugin = {'TitleID': titleid,
                                  'name': plugname,
                                  'developer': developer,
                                  'devsite': devsite,
                                  'desc': desc,
                                  'plg': plgp,
                                  'version': ver,
                                  'compatible': cpb,
                                  'pic': pic,
                                  'pid': plid,
                                  'user': cuser
                                  }
                        self.cdb.updatePlugin(**plugin)
                        message = "Your plugin was edited successfully"
                        succ = True
                    if succ:
                        message = messagehtml % ('success', message)
                    else:
                        message = messagehtml % ('danger', message)
                    page = message
                else:
                    pl = self.cdb.getPlugin(pid=plid)
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
                    'danger', 'You do not have permissions to edit this plugin.')
        else:
            page = messagehtml % (
                'danger', 'You cant add items because you are not logged in.')
        return page

    def rm(self):
        cuser, _ = self.checkAuth()
        args = parseURL(self.path)
        luser = self.cdb.getUser(email=cuser)
        if cuser:
            plugid = int(args['plugid'])
            plugin = self.cdb.getPlugin(pid=plugid)
            if plugin != None:
                if plugin['uploader'] == luser['email'] or luser["permissions"] <= database.ADMIN_LEVEL:
                    if 'sure' not in args:
                        plugin = self.cdb.getPlugin(pid=plugid)
                        pg = removal % (
                            plugid,
                            plugin['name'],
                            plugin['name'])
                        return pg
                    else:
                        self.cdb.removePlugin(user=cuser, pid=plugid)
                        return messagehtml % ('success', 'Your plugin was removed')
                else:
                    return messagehtml % ('danger', 'You dont have the permissions to delete this Plugin')
            else:
                return messagehtml % ('warning', 'No plugin with that ID found.')

###########################info zone##########################################

    def index(self):
        table = ""
        isSearch = False
        path = self.path[1:]
        parsed = parseURL(self.path)
        for item in self.cdb.getApproved():
            if not item["TitleID"] == "Not game":
                name = getgamebytid(item["TitleID"])
            else:
                name = ""
            if item['compatible'] == 'universal':
                cpbicon = iany
            elif item['compatible'] == 'n3ds':
                cpbicon = inew
            elif item['compatible'] == 'o3ds':
                cpbicon = iold
            table = table + links % (
                cpbicon,
                name,
                item["name"],
                item["added"],
                item['plg'],
                item['devsite'],
                item['id']
            )
        page = index % (table)
        return page

    def description(self):
        parsed = parseURL(self.path)
        if "id" in parsed:
            gid = int(parsed["id"])
            cuser, _ = self.checkAuth()
            luser = self.cdb.getUser(email=cuser)
            try:
                if luser["permissions"] <= database.ADMIN_LEVEL or gid in luser["plugins"]:
                    options = 'Options:<a href="edit?plugid=%s" class="btn btn-secondary btn-sm">Edit</a><a href="rm?plugid=%s" class="btn btn-danger btn-sm">Remove</a>' % (
                        parsed['id'], parsed['id'])
                else:
                    options = ''
            except KeyError:
                options = ''
            except TypeError:
                options = ''
            if self.cdb.getPlugin(pid=gid) != None:
                item = self.cdb.getPlugin(pid=gid)
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
        apidata = []
        for item in self.cdb.getApproved():
            del item["uploader"]
            del item["approved"]
            apidata.append(item)
        self.wfile.write(bytes(json.dumps(apidata), 'utf-8'))

###########################httplib zone########################################

    def do_GET(self):
        timer_start = time()
        speccall = False
        self.cookie = parseCookie(dict(self.headers))
        # print(sessions)
        # print(self.cookie)
        cuser, rcookies = self.checkAuth()
        luser = self.cdb.getUser(email=cuser)
        if cuser:
            if luser["permissions"] <= database.MOD_LEVEL:
                nbar = nbar_loggedin % (
                    cuser, '<a class="dropdown-item" href="mod">Moderation</a>')
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
                elif self.path.startswith('/light.css'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'text/css')
                    self.end_headers()
                    self.wfile.write(lighttheme)
                elif self.path.startswith('/dark.css'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'text/css')
                    self.end_headers()
                    self.wfile.write(darktheme)
                elif self.path.startswith('/error'):
                    1 / 0
                elif self.path.startswith('/rm'):
                    page = self.rm()
                else:
                    page = self.index()
                if not speccall:
                    timer_stop = time()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    page = base % (
                        nbar, page, version, str(timer_stop - timer_start))
                    self.wfile.write(bytes(page, 'utf-8'))
            except Exception as e:
                timer_stop = time()
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, messagehtml %
                               ('danger',
                                'Oops! An error occured when processing your request!'),
                               version, str(timer_stop - timer_start))
                self.wfile.write(bytes(page, 'utf-8'))
                raise e

    def do_POST(self):
        timer_start = time()
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
                timer_stop = time()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                if scookie:
                    self.send_header('Set-Cookie', 'AToken=%s' % (cookie))
                self.end_headers()
                self.wfile.write(
                    bytes(base % ("", page, version, str(timer_stop - timer_start)), 'utf-8'))
            else:
                timer_stop = time()
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(
                    bytes(base % ("", messagehtml % ('danger', 'Bad request!'), version, str(timer_stop - timer_start)), 'utf-8'))
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = base % (version, messagehtml %
                           ('danger', 'Oops! An error occured when processing your request!'), "", "Error")
            self.wfile.write(bytes(page, 'utf-8'))
            raise e


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    """Handle requests in a separate thread."""

db = database.database()
count = 0
for i in db.getAllPermissionUsers(database.OWNER_LEVEL):
    count += 1
if count == 0:
    email = input("Owner email: ")
    passwd = input("Owner Password: ")
    db.createOwner(email, passwd)
    del email
    del passwd

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
