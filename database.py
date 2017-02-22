import dataset
import json
import datetime
from custom_exception import MissingPermission, SQLException
import hashlib
from uuid import uuid4

PLUGIN_INFO= {'id': False, 
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
              'uploader': False}

USER_INFO={'uuid':False,
           'email':True,
           'hash':True,
           'plugins':True,
           'activate':False,
           'permissions':False}

OWNER_LEVEL= 0
ADMIN_LEVEL= 1
MOD_LEVEL= 2
USER_LEVEL= 3

class database():
    db=None
    plugins=None
    users=None
    def __init__(self):
        self.db=dataset.connect("sqlite:///plugs.db")
        self.plugins = self.db["Plugins"]
        self.users = self.db.get_table("users", primary_id='uuid', primary_type='String(36)')

#########################################Plugin#############################################

    def addPlugin(self, uploader, name, des, ver, dev, titleid, site, dwld, dsver, picture=""):
        now = datetime.datetime.now()
        user = self.getUser(email=uploader)
        if user!=None:
            if user['permissions']<=MOD_LEVEL:
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
                      'uploader': uploader}
            newid = self.plugins.insert(plugin)
            user['plugins'].append(newid)
            self.setUser(user)
            plugin = self.getPlugin(pid=newid)
            return plugin
        else:
            raise SQLException

    def allowPlugin(self, user, pid):
        user= self.getUser(email=user)
        if user!=None:    
            if user["permissions"]<=MOD_LEVEL:
                plugin = self.getPlugin(pid=pid)
                if plugin != None:
                    plugin["approved"]=True
                    self.plugins.update(plugin, ['id'])
                else:
                    raise SQLException("Not Found ID")
        else:
            raise BadUser("User Not Found")

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
        if user!=None:
            plugin = self.getPlugin(pid=pid)
            if plugin!=None:
                if user["permissions"]<=ADMIN_LEVEL or plugin['uploader']==user['email']:
                    for i in kwargs.keys():
                        try:
                            if PLUGIN_INFO[i]:
                                plugin[i]=kwargs[i]
                            else:
                                pass
                        except KeyError:
                            return False
                    self.setPlugin(plugin)
                    return plugin
                else:
                    raise MissingPermission("Missing Permissions")
            else:
                raise SQLException("Not Found ID")
        else:
            raise BadUser("User Not Found")

    def transferPluginOwner(self, user, pid, newUser):
        admin = self.getUser(email=user)
        if admin!=None:
            if admin["permission"] <= ADMIN_LEVEL:
                newOwner = self.getUser(email=newUser)
                plugin = self.getPlugin(pid=pid)
                previousOwner= self.getUser(plugin['uploader'])
                del previousOwner['plugins'][previousOwner['plugins'].index(plugin[id])]
                newOwner['plugins'].append(pid)
                plugin['uploader'] = newOwner['email']
                self.setPlugin(plugin)
                self.setUser(newOwner)
                self.setUser(previousOwner)
            else:
                raise MissingPermission("Missing Permissions")
        else:
            raise SQLException("Not Found ID")

    def removePlugin(self, user, pid):
        admin = self.getUser(user)
        plugin = self.getPlugin(pid=pid)
        if plugin!=None:
            if admin['permissions']<=ADMIN_LEVEL or plugin['uploader']==admin['email']:
                user=self.getUser(email=plugin["uploader"])
                del user["plugins"][user["plugins"].index(pid)]
                self.setUser(user)
                self.plugins.delete(id=pid)
                return True
            else:
                raise MissingPermission("Missing Permissions")
        else:
            raise SQLException("Not Found ID")


#######################################USER##########################################
    def computeMD5hash(self, string):
        m = hashlib.sha512()
        string = str(string)
        m.update(string.encode('utf-8'))
        return m.hexdigest()

    def addUser(self, email, password):
        hashp=self.computeMD5hash(password)
        del password
        user={'uuid': str(uuid4()), 
              'email': email, 
              'hash' : str(hashp), 
              'plugins': json.dumps([]),
              'activate': False,
              'permissions': USER_LEVEL}
        self.users.insert(user)
        return user

    def updateUser(self, loged, tomod,**kwargs):
        loged=self.getUser(email=loged)
        user=sef.getUser(email=tomod)
        if loged['email']==user['email']:
            for i in kwargs.keys():
                if i in USER_INFO:
                    if i=="hash":
                        phash = str(computeMD5hash(kwargs[i]))
                        del kwargs[i]
                        user[i] = phash
                    else:
                        user[i] = kwargs[i]
                else:
                    return False
        else:
            return False
        self.setUser(user)
        return True

    def deleteUser(self, user, todel):
        admin=self.getUser(user)
        todel=self.getUser(todel)
        if admin['permissions']<=ADMIN_LEVEL or admin[uuid]==todel[uuid]:
            for i in todel["plugins"]:
                self.removePlugin(i)
            self.users.delete(email=todel['email'])

        else:
            raise MissingPermission("Missing Permissions")

    def upgradePremis(self, user, upd, newPermissions):
        admin=self.getUser(email=user)
        if newPermissions<OWNER_LEVEL:
            return False
        if admin['permissions'] <= OWNER_LEVEL:
            upg = self.getUser(email=udp)
            if upg!=None:
                upg['permissions']== newPermissions
                self.setUser(upg)
                return True
            else:
                return False
        elif admin["permissions"] <= ADMIN_LEVEL:
            if newPermissions<=MOD_LEVEL:
                return False
            else:
                upg= self.getUser(email=udp)
                upg["permissions"] == newPermissions
                self.setUser(upg)
        else:
            return False

    def activateUser(self, uid):
        user = self.getUserUuid(uuid=uid)
        if user!=None:
            user["activate"] = True
            self.setUser(user)
            return True
        else:
            return False


######################################specific Getters and setters#####################################
#-----------------------------Users------------------------------------#
    def getUser(self, email):
        user = self.users.find_one(email=email)
        if user!=None:
            user["plugins"] = json.loads(user['plugins'])
        return user

    def getUserUuid(self, uuid):
        user = self.users.find_one(uuid=uuid)
        if user!=None:
            user["plugins"] = json.loads(user["plugins"])
        return user

    def getAllUsers(self):
        return self.users.all()

    def getAllPermissionUsers(self, permissionlevel=MOD_LEVEL):
        return self.users.find(permissions=permissionlevel)

    def setUser(self, user):
        user['plugins']=json.dumps(user['plugins'])
        self.users.update(user, ['email'])

    def createOwner(self, user, password):
        count=0
        for i in self.getAllPermissionUsers(OWNER_LEVEL):
            count+=1
        if count==0:
            hashp=self.computeMD5hash(password)
            del password
            user={'uuid': str(uuid4()), 
                  'email': user, 
                  'hash' : str(hashp), 
                  'plugins': json.dumps([]),
                  'activate': True,
                  'permissions': OWNER_LEVEL}
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
        if cld!=None:
            return cld
        else:
            return False

    def getApproved(self):
        return self.plugins.find(approved=True)

    def setPlugin(self, plugin):
        self.plugins.update(plugin, ['id'])