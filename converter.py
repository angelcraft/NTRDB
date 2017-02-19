import dataset
import pickles

with open('plugins.pickle', 'rb') as f:
    plugins = pickle.load(f)

with open('users.pickle', 'rb') as f:
    users = pickle.load(f)

{"1": {"TitleID": "0004000000198E00", 
       "name": "Animal Crossing: New Leaf Cheat-Menu", 
       "developer": "martor", 
       "devsite": "http://example.com/", 
       "desc": "asdf", 
       "plg": "http://example.com/example.plg", 
       "added": "2017-02-19 16:13", 
       "timestamp": 1487531598.60032, 
       "version": "3", 
       "compatible": "universal", 
       "pic": "http://rydog199.github.io/images/animal.png", 
       "approved": false}}

"martinmontane6@gmail.com": ["206c57add2a200e7ecd5ae2c184ea60d7a5bbc00e4d9b5560f4b00f290cbb6f8c2f7a6fdea735afd20462a7da4aac96882cc163409c2ef2f46262a8256406ce9", true, [1]]

db=dataset.connect("sqlite:///plugs.db")
usersdb=db.get_table("Users", primary_id="uuid", pirmary_type="String(36)")

for i in users.keys()
