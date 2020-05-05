from pymongo import MongoClient
import bcrypt

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.assignment
users = db.users

data = [
{
	"name": "Ben Martin",
	"username": "ben",
	"password": b"admin123",
	"email": "benmartin494@gmail.com",
	"admin": True
},
{
	"name": "William",
	"username": "will",
	"password": b"user123",
	"email": "william@gmail.com",
	"admin": False
}]

for new_user in data:
    new_user["password"] = bcrypt.hashpw(new_user["password"], bcrypt.gensalt())
    users.insert_one(new_user)

