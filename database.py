import dataset
import json
import datetime
from custom_exception import MissingPermission, SQLException, BadUser, Banned
import hashlib
from uuid import uuid4

#####################################config Variables########################################

MAX_STIKES = 6

PLUGIN_INFO = {'id': False,
               'TitleID': True,
               'name': True,
               'developer': True,
               'devsite': True,
               'desc': True,
               'plg': True,
               'added': False,
               'timestamp': False,
               'version': True,
               'compatible': True,
               'pic': True,
               'approved': True,
               'uploader': False,
               'likes': False}

USER_INFO = {'uuid': False,
             'email': True,
             'hash': True,
             'plugins': True,
             'activate': False,
             'permissions': False,
             'banned': True,
             'strikes': True,
             'passwd': True,
             'likes': True}

OWNER_LEVEL = 0
ADMIN_LEVEL = 1
MOD_LEVEL = 2
USER_LEVEL = 3
BAN_LEVEL = 4
#######################################module#############################################

class database():
    db = None
    plugins = None
    users = None

    def __init__(self):
        self.db = dataset.connect("sqlite:///plugs.db")
        self.plugins = self.db["Plugins"]
        self.users = self.db.get_table(
            "users", primary_id='uuid', primary_type='String(36)')

#########################################Plugin###########################

    def addPlugin(self, uploader, name, des, ver, dev, titleid, site, dwld, dsver, picture=""):
        now = datetime.datetime.now()
        user = self.getUser(email=uploader)
        if user['permissions'] <= MOD_LEVEL:
            approved = True
        else:
            approved = False
        plugin = {'TitleID': titleid,
                  'name': name,
                  'developer': dev,
                  'devsite': site,
                  'desc': des,
                  'plg': dwld,
                  'added': now.strftime("%Y-%m-%d %H:%M"),
                  'timestamp': now.timestamp(),
                  'version': ver,
                  'compatible': dsver,
                  'pic': picture,
                  'approved': approved,
                  'uploader': uploader,
                  'likes': 0}
        newid = self.plugins.insert(plugin)
        user['plugins'].append(newid)
        self.setUser(user)
        plugin = self.getPlugin(pid=newid)
        return plugin

    def allowPlugin(self, user, pid):
        user = self.getUser(email=user)
        if user["permissions"] <= MOD_LEVEL:
            plugin = self.getPlugin(pid=pid)
            if plugin != None:
                plugin["approved"] = True
                self.plugins.update(plugin, ['id'])
            else:
                raise SQLException("Plugin ID")
        else:
            raise MissingPermission("Moderator")

    def updatePlugin(self, user, pid, **kwargs):
        """Update a plugin. Checks the Array to make sure the field is available to modify

        Arguments:
            user -- loged users email
            pid -- Plugin ID 
            kwargs -- insert the key words or the fields you want to update
        Returns:
            if any of the kwargs keywords isn't True the array it will return a False.
            if all of the kwargs are in the array it will update and return the updated plugin
        """
        user = self.getUser(user)
        plugin = self.getPlugin(pid=pid)
        if plugin != None:
            if user["permissions"] <= ADMIN_LEVEL or plugin['uploader'] == user['email']:
                for i in kwargs.keys():
                    try:
                        if PLUGIN_INFO[i]:
                            plugin[i] = kwargs[i]
                        else:
                            pass
                    except KeyError:
                        return False
                self.setPlugin(plugin)
                return plugin
            else:
                raise MissingPermission("Admin or Uploader")
        else:
            raise SQLException("Plugin ID")

    def transferPluginOwner(self, user, pid, newUser):
        admin = self.getUser(email=user)
        if admin["permission"] <= ADMIN_LEVEL:
            newOwner = self.getUser(email=newUser)
            if newOwner != None:
                plugin = self.getPlugin(pid=pid)
                if plugin != None:
                    previousOwner = self.getUser(plugin['uploader'])
                    del previousOwner['plugins'][
                        previousOwner['plugins'].index(plugin[id])]
                    newOwner['plugins'].append(pid)
                    plugin['uploader'] = newOwner['email']
                    self.setPlugin(plugin)
                    self.setUser(newOwner)
                    self.setUser(previousOwner)
                else:
                    raise SQLException("Plugin")
            else:
                raise SQLException("User")
        else:
            raise MissingPermission("Admin")

    def removePlugin(self, user, pid):
        admin = self.getUser(user)
        plugin = self.getPlugin(pid=pid)
        if plugin != None:
            if admin['permissions'] <= ADMIN_LEVEL or plugin['uploader'] == admin['email'] or (admin['permissions']<=MOD_LEVEL and not plugin['approved']):
                user = self.getUser(email=plugin["uploader"])
                del user["plugins"][user["plugins"].index(pid)]
                self.setUser(user)
                self.plugins.delete(id=pid)
                return True
            else:
                raise MissingPermission("Admin or Uploader")
        else:
            raise SQLException("Plugin ID")

    def checkOwner(self, user, pid):
        user = self.getUser(user)
        if pid in user['plugins'] or user['permissions'] <= ADMIN_LEVEL:
            return True
        else:
            raise MissingPermission("Admin or Uploader")

    def likePlugin(self, user, pid):
        user = self.getUser(email=user)
        plugin = self.getPlugin(pid=pid)
        if plugin!=None:
            user['likes'].append(plugin['id'])
            plugin['likes']+=1
            self.setUser(user)
            self.setPlugin(plugin)
        else:
            raise SQLException("Plugin Id")

    def unlikePlugin(self, user, pid):
        user = self.getUser(email=user)
        plugin = self.getPlugin(pid=pid)
        if plugin!=None:
            del user['likes'][user['likes'].index(plugin['id'])]
            plugin['likes']-=1
            self.setUser(user)
            self.setPlugin(plugin)
        else:
            raise SQLException("Plugin Id")

    def doLike(self, user, pid):
        luser = self.getUser(email=user)
        if int(pid) in luser['likes']:
            self.unlikePlugin(user, pid)
        else:
            self.likePlugin(user, pid)

#######################################USER###############################
    def computeMD5hash(self, string):
        m = hashlib.sha512()
        string = str(string)
        m.update(string.encode('utf-8'))
        return m.hexdigest()

    def addUser(self, email, password):
        hashp = self.computeMD5hash(password)
        del password
        user = {'uuid': str(uuid4()),
                'email': email,
                'hash': str(hashp),
                'plugins': json.dumps([]),
                'activate': False,
                'permissions': USER_LEVEL,
                'banned': False,
                'strikes': -1,
                'likes': "[]"}
        self.users.insert(user)
        return user

    def updateUser(self, loged, tomod, **kwargs):
        loged = self.getUser(email=loged)
        user = self.getUser(email=tomod)
        if user != None:
            if loged['email'] == user['email']:
                for i in kwargs.keys():
                    if USER_INFO[i]:
                        if i == "passwd":
                            phash = str(self.computeMD5hash(kwargs[i]))
                            del kwargs[i]
                            user["hash"] = phash
                        else:
                            user[i] = kwargs[i]
                    else:
                        pass
            else:
                raise MissingPermission("User Creator")
            self.setUser(user)
            return True
        else:
            raise SQLException("User")

    def deleteUser(self, user, todel):
        admin = self.getUser(user)
        todel = self.getUser(todel)
        if todel != None:
            if admin['permissions'] <= ADMIN_LEVEL or admin[uuid] == todel[uuid]:
                for i in todel["plugins"]:
                    self.removePlugin(i)
                self.users.delete(email=todel['email'])
            else:
                raise MissingPermission("Admin or User Creator")
        else:
            raise SQLException("User")

    def upgradePermis(self, user, upd, newPermissions):
        admin = self.getUser(email=user)
        if newPermissions < OWNER_LEVEL:
            return False
        if admin['permissions'] <= OWNER_LEVEL:
            upg = self.getUser(email=upd)
            if upg != None:
                upg['permissions'] = newPermissions
                upg['banned'] = False
                self.setUser(upg)
                return True
            else:
                raise SQLException("User")
        elif admin["permissions"] <= ADMIN_LEVEL:
            if newPermissions <= ADMIN_LEVEL:
                raise MissingPermission("Owner")
            else:
                upg = self.getUser(email=upd)
                if upg != None:
                    upg["permissions"] = newPermissions
                    upg["banned"] = False
                    self.setUser(upg)
                    return True
                else:
                    raise SQLException("User")
        else:
            raise MissingPermission("Admin")

    def activateUser(self, uid):
        user = self.getUserUuid(uuid=uid)
        if user != None:
            user["activate"] = True
            self.setUser(user)
            return True
        else:
            raise SQLException("UUID")

    def checkPermission(self, user, level=MOD_LEVEL):
        user = self.getUser(email=user)
        if user['permissions'] <= level:
            return True
        else:
            raise MissingPermission(self.parsePerm(level))

    def banUser(self, user, toBan):
        user=self.getUser(email=user)
        ban = self.getUser(email=toBan)
        if user['permissions']<=ADMIN_LEVEL or user["email"] == ban["email"]:
            if ban!=None:
                ban['banned']=True
                ban['permissions']=BAN_LEVEL
                self.setUser(ban)
                return True
            else:
                raise SQLException("User")
        else:
            raise MissingPermission("Admin")

    def checkBan(self, user):
        user = self.getUser(email=user)
        if user['banned']:
            raise Banned("")
        else:
            return False

    def strikeUser(self, user, toStr):
        user = self.getUser(email=user)
        if user['permissions']<=MOD_LEVEL:
            strike = self.getUser(email=self.getPlugin(pid=toStr)['uploader'])
            if strike!=None:
                strike['strikes']+=1
                if strike['strikes']>=MAX_STIKES:
                    strike['banned']=True
                    strike['permissions']=BAN_LEVEL
                self.setUser(strike)
                self.removePlugin(user['email'], toStr)
                return True
            else:
                raise SQLException("Plugin's creator")
        else:
            raise MissingPermission("Moderator")
######################################specific Getters and setters########
#-----------------------------Users------------------------------------#
    def getUser(self, email):
        user = self.users.find_one(email=email)
        if user != None:
            user["plugins"] = json.loads(user['plugins'])
            user["likes"] = json.loads(user['likes'])
        return user

    def getUserUuid(self, uuid):
        user = self.users.find_one(uuid=uuid)
        if user != None:
            user["plugins"] = json.loads(user["plugins"])
        return user

    def getAllUsers(self):
        return self.users.all()

    def getAllPermissionUsers(self, permissionlevel=MOD_LEVEL):
        return self.users.find(permissions=permissionlevel)

    def setUser(self, user):
        user['plugins'] = json.dumps(user['plugins'])
        user['likes'] = json.dumps(user['likes'])
        self.users.update(user, ['email'])

    def createOwner(self, user, password):
        count = 0
        for i in self.getAllPermissionUsers(OWNER_LEVEL):
            count += 1
        if count == 0:
            hashp = self.computeMD5hash(password)
            del password
            user = {'uuid': str(uuid4()),
                    'email': user,
                    'hash': str(hashp),
                    'plugins': json.dumps([]),
                    'activate': True,
                    'permissions': OWNER_LEVEL,
                    'banned': False,
                    'strikes': -1,
                    'likes': "[]"}
            self.users.insert(user)

#-----------------------------Plugins----------------------------------#
    def getAllPlugins(self):
        return self.plugins.all()

    def getPlugin(self, pid):
        return self.plugins.find_one(id=pid)

    def getUserPlugins(self, user):
        return self.plugins.find(uploader=user)

    def getModPlugins(self):
        return self.plugins.find(approved=False)

    def getCloned(self, **kwargs):
        cld = self.plugins.find_one(**kwargs)
        if cld != None:
            return cld
        else:
            return False

    def getApproved(self):
        return self.plugins.find(approved=True)

    def setPlugin(self, plugin):
        self.plugins.update(plugin, ['id'])

######################################################OTHER#############################################
    def parsePerm(self, level):
        string = ""
        if level == OWNER_LEVEL:
            string = "Owner"
        elif level == ADMIN_LEVEL:
            string = "Admin"
        elif level == MOD_LEVEL:
            string == "Moderator"
        elif level == USER_LEVEL:
            string = "User"
        elif level == BAN_LEVEL:
            string = "Banned"
        return string
