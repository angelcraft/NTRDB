from os import listdir
from base64 import b64encode
themes = {}
with open('resources/favicon.png', 'rb') as f:
    favicon = f.read()
with open('resources/icon.png', 'rb') as f:
    icon = f.read()
with open('html/error.html') as f:
    error = f.read()
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
with open('html/links_manage.html') as f:
    links_mng = f.read()
with open('html/nbar_loggedin.html') as f:
    nbar_loggedin = f.read()
with open('html/nbar_login.html') as f:
    nbar_login = f.read()
with open('resources/MailRegText.txt') as f:
    actmsg = f.read()
with open('html/edit.html') as f:
    editpage = f.read()
with open('html/manage.html') as f:
    managepage = f.read()
with open('html/removal.html') as f:
    removal = f.read()
with open('html/links_mod.html') as f:
    links_mod = f.read()
with open('html/mod.html') as f:
    mod = f.read()
with open('resources/Icon_Any.png', 'rb') as f:
    iany = str(b64encode(f.read()), 'utf-8')
with open('resources/Icon_New.png', 'rb') as f:
    inew = str(b64encode(f.read()), 'utf-8')
with open('resources/Icon_Old.png', 'rb') as f:
    iold = str(b64encode(f.read()), 'utf-8')
for item in listdir('html/themes'):
    with open('html/themes/%s' % item, 'rb') as f:
        themes[item[:-4]] = f.read()
with open('html/adminmenu.html') as f:
    adminmenu = f.read()
with open('html/links_adminmenu.html') as f:
    links_adminmenu = f.read()
with open('html/thememenu.html') as f:
    thememenu = f.read()
with open('html/links_thememenu.html') as f:
    links_thememenu = f.read()
with open('resources/robots.txt', 'rb') as f:
    robots = f.read()
print("Pages loaded")
