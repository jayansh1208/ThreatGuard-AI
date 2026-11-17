import os, sys, json
# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)
# Now import
from backend.app.database.connection import get_db
client = get_db().client
# Use default database from connection uri
db = client.get_default_database()
cols = db.list_collection_names()
print('Collections:', cols)
for name in cols:
    indexes = list(db[name].list_indexes())
    print(f'Indexes for {name}:', [i['name'] for i in indexes])
