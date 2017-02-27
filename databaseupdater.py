import dataset
import sqlalchemy

db = dataset.connect("sqlite:///plugs.db")
table = db.get_table(
    "users", primary_id='uuid', primary_type='String(36)')

table.insert({"uuid": "aaaaaaa", "strikes": -1}, ensure=["strikes"])
table.delete(uuid="aaaaaaa")

for i in table.all():
    i['strikes'] = -1
    i['banned'] = False
    table.update(i, ['email'], ensure=['strikes'])
