import dataset
import pickle
from uuid import uuid4
import json

with open('plugins.pickle', 'rb') as f:
    plugins = pickle.load(f)

with open('users.pickle', 'rb') as f:
    users = pickle.load(f)

db=dataset.connect("sqlite:///plugs.db")
usersdb=db.get_table("Users", primary_id="uuid", primary_type="String(36)")
pluginsdb = db["Plugins"]
for i in dict(users).keys():
    email=i
    uuid=str(uuid4())
    phash=users[i][0]
    activate=users[i][1]
    plugins=json.dumps(users[i][2])
    newUser={'uuid': uuid, 'email': email, 'hash': phash, 'plugins': plugins, "activate": activate, "permissions": 3}
    if usersdb.find_one(email=email)==None:
      usersdb.insert(newUser)

with open('plugins.pickle', 'rb') as f:
    plugins = pickle.load(f)

def lookForUploader(pid):
  for i in usersdb.all():
    i["plugins"]=json.loads(i["plugins"])
    if pid in i["plugins"]:
      return i["email"]

apidata = {}
copy = dict(plugins)
for item in copy.keys():
  if item!=0:
    if pluginsdb.find_one(id=item)==None:
      plugin = copy[item]
      plugin['uploader'] = lookForUploader(item)
      pluginsdb.insert(plugin)