from chalicelib.config.application import *
# Import The Model
from chalicelib.app.models.user import User
# Write your Controller
@app.route('/users', methods=['POST'])
def create_user():
    # This is the JSON body the user sent in their POST request.
    user_as_json = app.current_request.json_body
    print(os.getenv('USERS_TABLE_NAME'))
    table_name = get_table_name()
    table = boto3.resource('dynamodb').Table(table_name)
    username = user_as_json['username']
    user_detail = User.find(user_as_json['username'])
    print('User Detail',username,user_detail)
    if user_detail != None:
        return {'error': 'Username has been taken.'}
    else:
        user = User(user_as_json)
        user.save()
        # We'll echo the json body back to the user in a 'user' key.
        return {'success': 'User was successfully created.'}
#
# See the README documentation for more examples.
#
@app.route('/login', methods=['POST'])
def login():
    body = app.current_request.json_body
    user = User.find(body['username'])
    if user == None:
        return {'error': 'User name or password is invalid.'}
    else:
        record = user.attributes()
        record['hash']= user.hash
        record['salt']= user.salt
        record['rounds']= user.rounds
        record['hashed']= user.hashed
        jwt_token = auth.get_jwt_token(body['username'], body['password'], record)
        return {'token': jwt_token}
@app.authorizer()
def jwt_auth(auth_request):
    token = auth_request.token
    print('Token',token)
    decoded = auth.decode_jwt_token(token)
    return AuthResponse(routes=['*'], principal_id=decoded['sub'])

@app.route('/me', methods=['GET'], authorizer=jwt_auth)
def get_user():
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    print('User Name:',username)
    return user.attributes()

@app.route('/me/update', methods=['POST'], authorizer=jwt_auth)
def update_current_user():
    body = app.current_request.json_body
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    if user != None:
        user.update_attributes(body)
        return_data = user.attributes()
    else:
        return_data = {'error': 'Record not found.'}
    return return_data

# Rest API code
def get_app_db():
    global _DB
    if _DB is None:
        _DB = db.DynamoDBTodo(
            boto3.resource('dynamodb').Table(
                os.environ['APP_TABLE_NAME'])
        )
    return _DB

def get_authorized_username(current_request):
    return current_request.context['authorizer']['principalId']
def get_table_name(stage=None):
    return os.environ['USERS_TABLE_NAME']

def encode_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    rounds = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password, salt, rounds)
    return {
        'hash': 'sha256',
        'salt': salt,
        'rounds': rounds,
        'hashed': hashed,
    }
