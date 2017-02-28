import dataset

db = dataset.connect("sqlite:///plugs.db")
table = db.get_table(
    "users", primary_id='uuid', primary_type='String(36)')
plugins=db['Plugins']

table.insert({"uuid": "aaaaaaa", "likes": "[]"}, ensure=["likes"])
table.delete(uuid="aaaaaaa")
plugins.insert({"likes": -88}, ensure=['likes'])
plugins.delete(likes=-88)

for i in table.all():
    i['likes'] = "[]"
    table.update(i, ['email'], ensure=['likes'])
for i in plugins.all():
    i['likes'] = 0
    plugins.update(i, ['id'], ensure=['likes'])