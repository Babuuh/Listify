import os
from datetime import datetime
import flask
from flask.globals import session
from flask.json import jsonify
import flask_sqlalchemy
import flask_praetorian
import flask_cors
from werkzeug.exceptions import Unauthorized
from sqlalchemy.exc import IntegrityError

db = flask_sqlalchemy.SQLAlchemy()
guard = flask_praetorian.Praetorian()
cors = flask_cors.CORS()


# A generic user model that might be used by an app powered by flask-praetorian
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    email = db.Column(db.Text, unique=True, nullable=False)
    first_name = db.Column(db.Text)
    second_name = db.Column(db.Text)
    date_of_birth = db.Column(db.String(120), nullable=True)
    password = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def rolenames(self):
        try:
            return self.roles.split(',')
        except Exception:
            return []

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    @property
    def identity(self):
        return self.id
    
    @property
    def is_authenticated(self):
        return True


# Initialize flask app for the example
app = flask.Flask(__name__, static_folder='../build', static_url_path=None)
app.debug = True
app.config['SECRET_KEY'] = 'top secret'
app.config['JWT_ACCESS_LIFESPAN'] = {'hours': 24}
app.config['JWT_REFRESH_LIFESPAN'] = {'days': 30}

# Initialize the flask-praetorian instance for the app
guard.init_app(app, User)

# Initialize a local database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'database.db')}"
db.init_app(app)

# Initializes CORS 
cors.init_app(app)



# Routes
@app.route('/api/')
#@flask_praetorian.auth_accepted
@flask_praetorian.auth_required
def home():
  	return {"Hello": "World"}, 200

@app.route('/api/register', methods=['POST'])
def register():
    req = flask.request.get_json(force=True)
    username = req.get("username")
    email = req.get('email')
    first_name = req.get("first_name")
    second_name = req.get("second_name")
    date_of_birth = req.get("date_of_birth")
    created_at = req.get("created_at") 
    password = req.get("password")
    hash_password = guard.hash_password(password)
    user = User(username=username, password=hash_password,email=email,
                first_name=first_name,second_name=second_name,
                created_at=created_at, date_of_birth=date_of_birth)

        #query the name and email in the database to check for existence
    query_name = User.query.filter_by(username = user.username).count()
    query_email = User.query.filter_by(email = user.email).count()

    try:
        db.session.add(user)
        db.session.commit()
        print('account successfully created for', user.username)
        return {"message": f'Account succefully created for {user.username}'}
    except IntegrityError:


        if query_name > 0:
            db.session.rollback()
            print('username exists')
            return {"message": f'username already exist! Try another name.'}
        elif query_email > 0 :
            db.session.rollback()
            print('email exists')
            return {"message": f'user with that email already exist! Try another email.'}


@app.route('/api/login', methods=['POST'])
def login():
    req = flask.request.get_json(force=True)
    username = req.get('username', None)
    password = req.get('password', None)
    user = guard.authenticate(username, password)
    ret = {'access_token': guard.encode_jwt_token(user)}
    return ret, 200


@app.route('/api/get-users', methods= ['GET'])
def get_user():
    users = User.query.all()

    all_users = []

    for user in users:
        id = user.id
        username = user.username
        email = user.email
        first_name = user.first_name
        second_name = user.second_name
        password = user.password
        joined_at = user.created_at

        app_user = {}
        app_user["id"] = id
        app_user["username"] = username
        app_user["email"] = email
        app_user["first_name"] = first_name
        app_user["second_name"] = second_name
        app_user["password"] = password
        app_user["joined at"] = joined_at

        all_users.append(app_user)
    return jsonify({"users":all_users})

    
@app.route('/api/refresh', methods=['POST'])
def refresh():
    #Refreshes an existing JWT by creating a new one that is a copy of the old
    print("refresh request")
    old_token = flask.request.get_data()
    new_token = guard.refresh_jwt_token(old_token)
    ret = {'access_token': new_token}
    return ret, 200


@app.route('/api/profile')
#@flask_praetorian.auth_accepted
@flask_praetorian.auth_required
def protected():
    user = []
    name = flask_praetorian.current_user().username
    email = flask_praetorian.current_user().email
    first_name = flask_praetorian.current_user().first_name
    second_name = flask_praetorian.current_user().second_name
    DOB = flask_praetorian.current_user().date_of_birth
     
    user.append(name)
    user.append(email)
    user.append(first_name)
    user.append(second_name)
    user.append(DOB)

    return {"user": user}

@app.route('/api/get-session')
@flask_praetorian.auth_required
#@flask_praetorian.auth_accepted
def checkIsAuthenticated():
    current_user = flask_praetorian.current_user()
    if current_user.is_authenticated:
        isLoggedIn = True
        print('Authenticated', isLoggedIn) 
        return {"isLoggedIn":isLoggedIn} 
    else:
        isLoggedIn = False
        print('Unauthorized', isLoggedIn)
        return {"isLoggedIn":isLoggedIn} 

# Run the api
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)