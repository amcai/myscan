import pymongo
try:
    conn = pymongo.MongoClient("127.0.0.1",27017,socketTimeoutMS=3000)
    dbname = conn.list_database_names()
    if dbname:
        print(dbname)
except Exception as e:
    pass