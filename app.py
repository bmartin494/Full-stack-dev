from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId, json_util
import jwt, datetime, bcrypt
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = 'mysecret'

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.assignment   #select the database
parks = db.locations   #select the collection
users = db.users    #for user login
blacklist = db.blacklist    #for removing logged out tokens


def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({ 'message' : 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify( {'message' : 'Token is invalid'}), 401
        bl_token = blacklist.find_one({"token":token})
        if bl_token is not None:
            return make_response(jsonify({ 'message':'Token has been cancelled'}), 401)
        return func(*args, **kwargs)
    return jwt_required_wrapper
    

def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({ 'message' : 'Admin access required'}), 401)
    return admin_required_wrapper

@app.route("/api/v1.0/parks", methods=["GET"])
def show_all_parks():
    page_num, page_size = 1, 10
    if request.args.get('pn'):
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))
    
    
    data_to_return = []
    for park in parks.find(
    {}, { "Facility":1, "Address":1, "Cvan_Park":1, "Park":1, "Play_area":1, "Trail":1, "Water_Rec":1, "Type":1, "comments":1 }).skip(page_start).limit(page_size):
        park['_id'] = str(park['_id'])
        for comment in park['comments']:
            comment['_id'] = str(comment['_id'])
        data_to_return.append(park)
        
    return make_response(jsonify(data_to_return), 200)
    

@app.route("/api/v1.0/parks/<string:id>", methods=["GET"])
def show_one_park(id):
    park = parks.find_one(
        {'_id':ObjectId(id)},
        { "Facility":1, "Address":1, "Cvan_Park":1, "Park":1, "Play_area":1, "Trail":1, "Water_Rec":1, "Type":1, "comments":1, "coordinates":1 })
    if park is not None:
        park['_id'] = str(park['_id'])
        for comment in park['comments']:
            comment['_id'] = str(comment['_id'])
        return make_response( jsonify( park ), 200)
    else:
        return make_response( jsonify ({ "error" : "Invalid record ID" }), 404)


@app.route("/api/v1.0/parks", methods=["POST"])
def add_park():
    if "facility" in request.form and "address" in request.form and "cvanPark" in request.form and "park" in request.form and "playArea" in request.form and "trail" in request.form and "type" in request.form and "waterRec" in request.form:
                new_park = {
                                "Facility" : request.form["facility"],
                                "Address" : request.form["address"],
                                "Cvan_Park" : request.form["cvanPark"],
                                "Park" : request.form["park"],
                                "Play_Area" : request.form["playArea"],
                                "Trail" : request.form["trail"],
                                "Water_Rec" : request.form["waterRec"],
                                "Type" : request.form["type"],
                                "comments" : []
                            }
                new_park_id = parks.insert_one(new_park)
                new_park_link = "http://localhost:5000/api/v1.0/parks/" + str(new_park_id.inserted_id)
                return make_response( jsonify( {"url": new_park_link} ), 201)
    else:
        return make_response( jsonify( {"error":"Missing form data"} ), 404)



@app.route("/api/v1.0/parks/<string:id>", methods=["PUT"])
def edit_park(id):
        if "facility" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Facility" : request.form["facility"]}})
        if "address" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Address" : request.form["address"]}})
        if "cvanPark" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Cvan_Park" : request.form["cvanPark"]}})
        if "park" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Park" : request.form["park"]}})
        if "playArea" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Play_area" : request.form["playArea"]}})
        if "trail" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Trail" : request.form["trail"]}})
        if "waterRec" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Water_Rec" : request.form["waterRec"]}})
        if "type" in request.form:
            result = parks.update_one(
            {"_id" : ObjectId(id)}, {"$set" : {"Type" : request.form["type"]}})
        if result.matched_count == 1:
            edited_parks_link = "http://localhost:5000/api/v1.0/parks/" + id
            return make_response( jsonify( {"url":edited_parks_link}), 200)
        else:
            return make_response( jsonify({ "error" : "Invalid record ID" }), 404)
            
@app.route("/api/v1.0/parks/<string:id>", methods=["DELETE"])
@jwt_required
@admin_required
def delete_park(id):
    result = parks.delete_one({ "_id" : ObjectId(id)})
    if result.deleted_count == 1:
        return make_response( jsonify ( {} ), 204)
    else:
        return make_response( jsonify ( {"error" : " Invalid record ID"}), 404)
        
        
@app.route("/api/v1.0/parks/<string:id>/comments", methods=["GET"])
def fetch_all_comments(id):
    data_to_return = []
    park = parks.find_one( { "_id" : ObjectId(id)}, { "comments" : 1, "_id" : 0})
    for comment in park["comments"]:
        comment["_id"] = str(comment["_id"])
        data_to_return.append(comment)
    return make_response( jsonify( data_to_return ), 200 )


@app.route("/api/v1.0/parks/<string:park_id>/comments", methods=["POST"])
@jwt_required
def add_new_comment(park_id):
    if request.form["username"] != "" and "username" in request.form:
        if request.form["text"] != "" and "text" in request.form:
            try:
                val = int(request.form["stars"])
                if val >= 1 or val <=5 and "stars" in request.form:
                    new_comment = {
                            "_id" : ObjectId(),
                            "username" : request.form["username"],
                            "text" : request.form["text"],
                            "stars" : request.form["stars"],
                            "date" : request.form["date"],
                            "votes" : {}
                        }
                    parks.update_one( \
                    {"_id" : ObjectId(park_id)}, {"$push" : {"comments":new_comment}})
                    new_comment_link = "http://localhost:5000/api/v1.0/parks/" + park_id + "/comments/" + str(new_comment['_id'])
                    return make_response( jsonify( { "url" : new_comment_link } ),\
                    201 )
                else:
                    return make_response( jsonify( {"error" : "Stars rating must be 1-5"}))
            except ValueError:
                    return make_response( jsonify( {"error" : "Stars rating is not an integer"}), 404)
        else:
            return make_response( jsonify( { "error" : "Text field must be filled in"}))
    else:
        return make_response( jsonify( { "error" : "Username field must be filled in"}))


@app.route("/api/v1.0/parks/<string:p_id>/comments/<string:c_id>", methods=["GET"])
def fetch_one_comment(p_id, c_id):
    park = parks.find_one({ "comments._id" : ObjectId(c_id)}, { "_id" : 0, "comments.$" : 1} )
    if park is None:
        return make_response( jsonify( {"error" : "Invalid record ID or comment ID"}), 404)
    park['comments'][0]['_id'] = str(park['comments'][0]['_id'])
    
    return make_response( jsonify( park['comments'][0]), 200)


@app.route("/api/v1.0/parks/<string:p_id>/comments/<string:c_id>", methods=["PUT"])
def edit_review(p_id, c_id):
        edited_comment = {
            "comments.$.username" : request.form["username"],
            "comments.$.comment" : request.form["comment"],
            "comments.$.stars" : request.form["stars"],
            "comments.$.date" : request.form["date"]
        }
        parks.update_one( {"comments._id" : ObjectId(c_id)}, {"$set" : edited_comment})
        edited_comment_url = "http://localhost:500/api/v1.0/parks/" + p_id + "/comments/" + c_id
        return make_response( jsonify ( {"url":edited_comment_url} ), 200)


@app.route("/api/v1.0/parks/<string:p_id>/comments/<string:c_id>", methods=["DELETE"])
@jwt_required
@admin_required
def delete_comment(p_id, c_id):
    parks.update_one( {"_id" : ObjectId(p_id)}, {"$pull" : {"comments" : { "_id" : ObjectId(c_id) }}} )
    return make_response( jsonify ( {} ), 204)
    


@app.route('/api/v1.0/login', methods=['GET'])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one({'username':auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):
                token = jwt.encode({
                    'user' : auth.username,
                    'admin' : user["admin"],
                    'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
                return make_response( jsonify({'token' : token.decode('UTF-8')}), 200)
            else:
                return make_response( jsonify({ 'message':'Bad password'}), 401)
        else:
            return make_response(jsonify({ 'message':'Bad username'}), 401)
    return make_response(jsonify({ 'message':'Authentication required'}), 401)


@app.route('/api/v1.0/logout', methods=['GET'])
@jwt_required
def logout():
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    if not token:
        return make_response( jsonify({ 'message':'Token is missing'}), 401)
    else:
        blacklist.insert_one({"token":token})
        return make_response(jsonify({ 'message':'Logout successful'}), 200)
        

if __name__ == "__main__":
    app.run(debug=True)
