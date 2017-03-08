from urllib.parse import urlencode
import linecache
import smtplib
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
#from os.path import exists
import datetime
from urllib.parse import unquote
import json
import hashlib
from socketserver import ThreadingMixIn
#import threading
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
#import dataset
from os import devnull
from sys import exc_info
from custom_exception import MissingPermission, SQLException, BadUser, Banned
import database

##################################config vairables########################

##########################################################################
DEVNULL = open(devnull, 'w')
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int,
                    help='Port for receiving requests', required=False)
parser.add_argument('--tests', type=bool,
                    help='This is passed when tests happen', required=False)
args = parser.parse_args()
port = args.port
tests = args.tests
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
sessions = {}
uthemes = {}


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
    __version__ = "NTRDB/2.7"

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
            try:
                if args is not False:
                    if 'email' in args:
                        user = self.cdb.getUser(email=args['email'])
                        if user != None:
                            phash = computeMD5hash(args['pword'])
                            if user['activate'] and not self.cdb.checkBan(user['email']):
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
            except Banned as ex:
                raise ex
        return page, cookie

    def register(self, parsed):
        if self.checkAuth()[0]:
            return "<META HTTP-EQUIV=\"refresh\" CONTENT=\"1; URL=index\">"
        else:
            if not parsed:
                return reg_page
            else:
                mail = parsed['email']
                if 'pword' in parsed:
                    if len(parsed['pword']) > 3:
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
                                """
                                return messagehtml % (
                                    'danger', "This email is already registered")
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
                    else:
                        return messagehtml % ('danger', "You password is very short! Minimum is 4 symbols")
                else:
                    return messagehtml % ("danger", "You havent specifed password")

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
        try:
            if 'id' in args:
                uid = args['id']
                if self.cdb.activateUser(uid=uid):
                    page = messagehtml % (
                        'success', 'You successfully activated account!')
            else:
                page = messagehtml % (
                    'danger', 'Looks like you got bad link :(')
            return page
        except SQLException as e:
            raise e

    def logout(self):
        cuser = self.checkAuth()[0]
        if cuser:
            self.send_response(200)
            self.send_header('Set-Cookie', 'AToken=%s;HttpOnly;%s' %
                             (self.cookie['AToken'], 'Expires=Wed, 21 Oct 2007 07:28:00 GMT'))
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            page = messagehtml % ('success', 'You logged out')
            self.wfile.write(bytes(base % ('', page, version, '0'), 'utf-8'))
            del sessions[computeMD5hash(self.cookie['AToken'])]
        else:
            page = base % ('', messagehtml % ('danger', "<center><figure class=\"figure\">"
                                              "<img src=\"http://share.mostmodest.ru/2017/02/H2hgPCa.png\" class=\"figure-img img-fluid rounded\" alt=\"meme\">"
                                              "<figcaption class=\"figure-caption\">You cant logout if you are not logged in.</figcaption>"
                                              "</figure></center>"), version, '0')
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(page, 'utf-8'))
        return

    def adminmenu(self):
        table = ''
        cuser = self.checkAuth()[0]
        path = self.path[1:]
        if cuser:
            luser = self.cdb.getUser(email=cuser)
            parsed = parseURL(self.path)
            if not parsed:
                try:
                    if self.cdb.checkPermission(cuser, database.OWNER_LEVEL):
                        for i in self.cdb.getAllUsers():
                            table = table + links_adminmenu % (
                                i['email'],
                                i['permissions'],
                                "<a href='adminmenu?user=%s' class='btn btn-info btn-sm'>User</a>" % (i[
                                                                                                      'email']),
                                "<a href='adminmenu?moder=%s' class='btn btn-info btn-sm'>Moderator</a>" % (i[
                                                                                                            'email']),
                                "<a href='adminmenu?admin=%s' class='btn btn-info btn-sm'>Administrator</a>" % (i[
                                                                                                                'email']),
                                "<a href='adminmenu?ban=%s' class='btn btn-danger btn-sm'>Ban</a>" % (i[
                                    'email'])
                            )
                        page = adminmenu % (table)

                except MissingPermission as e:
                    try:
                        if self.cdb.checkPermission(cuser, database.ADMIN_LEVEL):
                            for i in self.cdb.getAllUsers():
                                if i['permissions'] >= database.MOD_LEVEL:
                                    table = table + links_adminmenu % (
                                        i['email'],
                                        i['permissions'],
                                        "<a href='adminmenu?user=%s' class='btn btn-info btn-sm'>User</a>" % (i[
                                                                                                              'email']),
                                        "<a href='adminmenu?moder=%s' class='btn btn-info btn-sm'>Moderator</a>" % (i[
                                                                                                                    'email']),
                                        "<a href='adminmenu?ban=%s' class='btn btn-danger btn-sm'>Ban</a>" % (i[
                                            'email']),
                                        ""
                                    )
                            page = adminmenu % (table)
                    except MissingPermission as ex:
                        raise ex
            elif 'user' in parsed:
                self.cdb.upgradePermis(
                    cuser, parsed['user'], database.USER_LEVEL)
                page = messagehtml % (
                    'success', 'User ' + parsed['user'] + ' is now user')
            elif 'moder' in parsed:
                self.cdb.upgradePermis(
                    cuser, parsed['moder'], database.MOD_LEVEL)
                page = messagehtml % (
                    'success', 'User ' + parsed['moder'] + ' is now Moderator')
            elif 'admin' in parsed:
                self.cdb.upgradePermis(
                    cuser, parsed['admin'], database.ADMIN_LEVEL)
                page = messagehtml % (
                    'success', 'User ' + parsed['admin'] + ' is now Administrator')
            elif 'ban' in parsed:
                self.cdb.banUser(cuser, parsed['ban'])
                page = messagehtml % (
                    'success', 'User ' + parsed['ban'] + ' is now Banned')
            return page
        else:
            raise BadUser("You have to log in to use this Page")


#######################Plugin managment zone#################################
    def moderator(self):
        table = ""
        path = self.path[1:]
        cuser, _ = self.checkAuth()
        try:
            if cuser:
                if self.cdb.checkPermission(cuser):
                    parsed = parseURL(self.path)
                    if not parsed:
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
                                item['id'],
                                item['id']
                            )
                        page = mod % (table)
                    elif 'allow' in parsed:
                        plid = int(parsed['allow'])
                        self.cdb.allowPlugin(cuser, plid)
                        page = messagehtml % (
                            'success', 'Plugin was approved!')
                    elif 'strike' in parsed:
                        plid = int(parsed['strike'])
                        self.cdb.strikeUser(cuser, plid)
                        page = messagehtml % (
                            'info', "The Plugin's uploader will recieve a strike")
                else:
                    raise MissingPermission("Moderator")
            else:
                raise BadUser("You can't moderate if you are not logged in")
        except SQLException as ex:
            raise ex
        except MissingPermission as ex:
            raise ex
        return page

    def additem(self):
        cuser = self.checkAuth()[0]
        if cuser:
            message = ""
            parsed = parseURL(self.path)
            if 'add' in parsed:
                plgp = parsed["link"]
                titleid_str = parsed['tid'].upper()
                titleid = parsed['tid'].upper().split(';')
                # print(titleid)
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
                if titleid_str == "":
                    titleid_str = "Not game"
                else:
                    for item in titleid:
                        if not len(item) == 16:
                            message = "One of TitleIDs is invalid!"
                            badreq = True
                            succ = False
                if plugname == "":
                    message = "You havent entered plugin's name!"
                    badreq = True
                    succ = False
                elif not url(plgp) or not url(pic) and not pic == '' or not url(devsite):
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
                        cuser, plugname, desc, ver, developer, titleid_str, devsite, plgp, cpb, pic)
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
            raise BadUser("You can't add Plugins if you are not logged in")
        return page

    def manage(self):
        cuser, _ = self.checkAuth()
        try:
            if cuser:
                uplg = []
                table = ''
                user = None
                try:
                    if self.cdb.checkPermission(cuser, database.ADMIN_LEVEL):
                        plglist = self.cdb.getAllPlugins()
                        for item in plglist:
                            uplg.append(item)

                except MissingPermission as ex:
                    user = self.cdb.getUser(email=cuser)
                    for item in user['plugins']:
                        plug = self.cdb.getPlugin(pid=item)
                        if plug:
                            uplg.append(plug)
                for plugin in uplg:
                    item = plugin['id']
                    table = table + \
                        links_mng % (
                            plugin['name'], plugin['added'], plugin['id'], plugin['id'])
                return managepage % table
            else:
                raise BadUser(
                    'You cant manage your plugins because you are not logged in')
        except MissingPermission as ex:
            raise ex

    def edit(self):
        args = parseURL(self.path)
        plid = int(args['plugid'])
        cuser = self.checkAuth()[0]
        if cuser:
            try:
                if self.cdb.checkOwner(cuser, plid):
                    message = ""
                    if 'edit' in args:
                        plgp = args["link"]
                        titleid_str = args['tid'].upper()
                        titleid = args['tid'].upper().split(';')
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
                        if titleid_str == "":
                            titleid_str = "Not game"
                        else:
                            for item in titleid:
                                if not len(item) == 16:
                                    message = "One of TitleIDs is invalid!"
                                    badreq = True
                                    succ = False
                        if plugname == "":
                            message = "You havent entered plugin's name!"
                            badreq = True
                            succ = False
                        if not url(plgp) or not url(pic) and not pic == '' or not url(devsite):
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
                            plugin = {'TitleID': titleid_str,
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
            except MissingPermission as ex:
                raise ex
            except SQLException as ex:
                raise ex
        else:
            raise BadUser('You cant add items because you are not logged in.')
        return page

    def rm(self):
        cuser, _ = self.checkAuth()
        args = parseURL(self.path)
        if cuser:
            plugid = int(args['plugid'])
            plugin = self.cdb.getPlugin(pid=plugid)
            try:
                if self.cdb.checkOwner(cuser, plugid):
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
            except MissingPermission as ex:
                raise ex
            except SQLException as ex:
                raise ex
        else:
            raise BadUser("You need to log in to delete Plugins")

###########################info zone##########################################

    def index(self):
        table = ""
        isSearch = False
        parsed = parseURL(self.path)
        count = 0
        cuser, _ = self.checkAuth()
        if "like" in parsed:
            if cuser:
                user = self.cdb.getUser(cuser)
                self.cdb.doLike(cuser, parsed['like'])
            else:
                raise BadUser("You have to login to like plugins")
        for item in self.cdb.getApproved():
            count = count + 1
            name = "For "
            # print(item["TitleID"])
            if not item["TitleID"] == "Not game":
                for game in item["TitleID"].split(";"):
                    name = name + getgamebytid(game) + ', '
                name = name[:-2]
            else:
                name = ''
            if item['compatible'] == 'universal':
                cpbicon = iany
            elif item['compatible'] == 'n3ds':
                cpbicon = inew
            elif item['compatible'] == 'o3ds':
                cpbicon = iold
            if item['pic'] == '':
                pic = 'http://vignette1.wikia.nocookie.net/mario/images/6/61/Item_Box_(Mario_Kart_8).png/revision/latest/scale-to-width-down/550?cb=20140505194326'
            else:
                pic = item['pic']

            if cuser:
                user = self.cdb.getUser(email=cuser)
                if item['id'] in user['likes']:
                    like = "<li class='list-group-item'><a href='index?like=%s#%s'><i class= 'fa fa-%s fa-fw' arua-hedden='true'></i> %sLike %s</a></li>" % (item['id'], item['id'], "heart-o", "Un", item['likes'])
                else:
                    like = "<li class='list-group-item'><a href='index?like=%s#%s'><i class= 'fa fa-%s fa-fw' arua-hedden='true'></i> %sLike %s</a></li>" % (item['id'], item['id'], "heart", "", item['likes'])
            else:
                like = "<li class='list-group-item'><a><i class= 'fa fa-%s fa-fw' arua-hedden='true'></i> %sLikes: %s</a></li>" % ("heart", "", item['likes'])
            table = table + links % (
                count,
                item['name'],
                item["desc"].replace('\n', '<br>'),
                item["id"],
                pic,
                count,
                pic,
                item["name"],
                name,
                item['version'],
                item['developer'],
                count,
                item['plg'],
                item['devsite'],
                like,
                cpbicon,
                item["added"],
                item['id'],
            )
        if count == 0:
            table = "<center><h3>No items :(</h3></center>"
        u = self.checkAuth()[0]
        if u:
            u = "Welcome back, %s!" % (str(u))
        else:
            u = "Hello, Guest! How about <a href=\"#\" onclick=\"event.preventDefault();$('#reg').modal('toggle')\">registering</a> or <a href=\"#\" onclick=\"event.preventDefault();$('#login').modal('toggle')\">logging in?</a> :)"
        page = index % (count, u, table)
        return page

    def themeswitch(self):
        user = self.checkAuth()[0]
        if user:
            parsed = parseURL(self.path)
            if len(parsed) > 0:
                if parsed['theme'] in themes:
                    uthemes[user] = parsed['theme']
                    return messagehtml % ('success', 'Your theme was switched!')
                else:
                    return messagehtml % ('danger', 'Looks like theme you chosen is bad :(')
            else:
                table = ''
                for item in themes:
                    link = {'theme': item}
                    table = table + links_thememenu % (item, urlencode(link))
                page = thememenu % (table)
                return page
        else:
            return messagehtml % ('danger', escape('You must be logged in to use themes!'))

    def description(self):
        parsed = parseURL(self.path)
        if "pid" in parsed:
            gid = int(parsed["pid"])
            cuser, _ = self.checkAuth()
            luser = self.cdb.getUser(email=cuser)
            try:
                if self.cdb.checkPermission(cuser, database.ADMIN_LEVEL):
                    options = 'Options:<a href="edit?plugid=%s" class="btn btn-secondary btn-sm">Edit</a><a href="rm?plugid=%s" class="btn btn-danger btn-sm">Remove</a>' % (
                        parsed['pid'], parsed['pid'])
            except MissingPermission as ex:
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
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        apidata = []
        for item in self.cdb.getApproved():
            del item["uploader"]
            del item["approved"]
            apidata.append(item)
        self.wfile.write(bytes(json.dumps(apidata, sort_keys=True, indent=2), 'utf-8'))

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
            if luser["permissions"] <= database.ADMIN_LEVEL:
                nbar = nbar_loggedin % (
                    cuser, '<a class="dropdown-item" href="mod">Moderation</a>', '<a class="dropdown-item" href="adminmenu">Administration</a>')
            elif luser["permissions"] <= database.MOD_LEVEL:
                nbar = nbar_loggedin % (
                    cuser, '<a class="dropdown-item" href="mod">Moderation</a>', '')
            elif luser["permissions"] <= database.USER_LEVEL:
                nbar = nbar_loggedin % (
                    cuser, '', '')
            elif luser["permissions"] <= database.BAN_LEVEL:
                page = self.logout()
                speccall = True
        else:
            nbar = nbar_login
        if not rcookies:
            try:
                if self.path.startswith('/robot'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(robots)
                elif self.path.startswith('/bstheme.css'):
                    speccall = True
                    user = self.checkAuth()[0]
                    if not user:
                        theme = themes['NTRDB(Cosmo)']
                    else:
                        if user in uthemes:
                            if uthemes[user] in themes:
                                theme = themes[uthemes[user]]
                            else:
                                # Fallback to default theme
                                theme = themes['NTRDB(Cosmo)']
                        else:
                            theme = themes['NTRDB(Cosmo)']
                    self.send_response(200)
                    self.send_header('Content-type', 'text/css')
                    self.end_headers()
                    self.wfile.write(theme)
                if self.path.startswith('/api'):
                    speccall = True
                    self.api()
                if self.path.startswith('/themes'):
                    page = self.themeswitch()
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
                elif self.path.startswith('/icon'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'image/png')
                    self.end_headers()
                    self.wfile.write(icon)
                elif self.path.startswith('/favicon'):
                    speccall = True
                    self.send_response(200)
                    self.send_header('Content-type', 'image/png')
                    self.end_headers()
                    self.wfile.write(favicon)
                elif self.path.startswith('/error'):
                    1 / 0  # LIKE
                elif self.path.startswith('/rm'):
                    page = self.rm()
                elif self.path.startswith('/adminmenu'):
                    page = self.adminmenu()
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
            except Banned as ex:
                timer_stop = time()
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, messagehtml %
                               ('danger',
                                'This account is Banned'),
                               version, str(timer_stop - timer_start))
                self.wfile.write(bytes(page, 'utf-8'))
            except BadUser as ex:
                timer_stop = time()
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, messagehtml %
                               ('danger',
                                str(ex)),
                               version, str(timer_stop - timer_start))
                self.wfile.write(bytes(page, 'utf-8'))
            except SQLException as ex:
                timer_stop = time()
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, messagehtml %
                               ('danger',
                                'The ' + str(ex) + ' requested was not found'),
                               version, str(timer_stop - timer_start))
                self.wfile.write(bytes(page, 'utf-8'))
            except MissingPermission as mp:
                timer_stop = time()
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, messagehtml %
                               ('danger',
                                'You need to be an ' + str(mp) + ' to be able to use this page.'),
                               version, str(timer_stop - timer_start))
                self.wfile.write(bytes(page, 'utf-8'))
            except Exception as e:
                timer_stop = time()
                exc_type, exc_obj, tb = exc_info()
                f = tb.tb_frame
                lineno = tb.tb_lineno
                filename = f.f_code.co_filename
                linecache.checkcache(filename)
                errorinfo = "File: %s<br>Line: %s<br>Error: %s" % (
                    filename, lineno, type(e).__name__
                )
                self.send_response(500)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                page = base % (nbar, error %
                               (errorinfo,
                                ),
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
        except Banned as ex:
            timer_stop = time()
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(
                bytes(base % ("", messagehtml % ('danger', 'This account is Banned'), version, str(timer_stop - timer_start)), 'utf-8'))
        except Exception as e:
            timer_stop = time()
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(
                bytes(base % ("", messagehtml % ('danger', 'Oops! An error occured when processing your request!'), version, str(timer_stop - timer_start)), 'utf-8'))
            raise e


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    """Handle requests in a separate thread."""


db = database.database()
count = 0
for i in db.getAllPermissionUsers(database.OWNER_LEVEL):
    count += 1
if count == 0:
    if not tests:
        mail = input("Owner email: ")
        passwd = input("Owner Password: ")
    else:
        mail = 'test@test.test'
        passwd = 'test'
    db.createOwner(mail, passwd)
    del mail
    del passwd
try:
    if port:
        server = ThreadedHTTPServer(('127.0.0.1', port), myHandler)
    else:
        server = ThreadedHTTPServer(('127.0.0.1', 8080), myHandler)

    print('Started httpserver')

    # Wait forever for incoming http requests
    server.serve_forever()
except KeyboardInterrupt:
    pass
