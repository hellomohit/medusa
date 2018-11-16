from chalicelib.config.application import *
from chalicelib.config.application import _get_parts
# Import The Model
from chalicelib.app.models.user import User,S3,USER_BUCKET
import cgi
from io import BytesIO


# Write your Controller
@app.route('/users/password/new',content_types=['multipart/form-data','application/json'], methods=['POST'])
def forgot_password():
    return User.generate_reset_password_token(app.current_request.json_body)

@app.route('/users/password',content_types=['multipart/form-data','application/json'], methods=['POST'])
def user_update_password():
    return User.validate_reset_password_token(app.current_request.json_body)

@app.route('/users', methods=['POST'])
def create_user():
    # This is the JSON body the user sent in their POST request.
    user_as_json = app.current_request.json_body
    table_name = get_table_name()
    table = boto3.resource('dynamodb').Table(table_name)
    username = user_as_json['username']
    user_detail = User.find(user_as_json['username'])
    if user_detail != None:
        return {'error': 'Username has been taken.'}
    else:
        user = User(user_as_json)
        user.save()
        record = user.attributes()
        record['hash']= user.hash
        record['salt']= user.salt
        record['rounds']= user.rounds
        record['hashed']= user.hashed
        jwt_token = auth.get_jwt_token(user_as_json['username'], user_as_json['password'], record)
        # We'll echo the json body back to the user in a 'user' key.
        return {'success': 'User was successfully created.','token': jwt_token}
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
    decoded = auth.decode_jwt_token(token)
    return AuthResponse(routes=['*'], principal_id=decoded['sub'])

@app.route('/me', methods=['GET'], authorizer=jwt_auth)
def get_user():
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    return user.attributes()

@app.route('/me/update', methods=['POST','PUT'], authorizer=jwt_auth)
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
@app.route('/me/upload', methods=['POST'],
           content_types=['multipart/form-data'], authorizer=jwt_auth)
def upload():
    files = _get_parts()
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    user.update_profile_pic(files['file'].filename,files['file'].value)
    return {
        "uploaded": "true",
        "profile_pic_url": user.get_profile_pic(),
    }

@app.route('/me/update_pic/{file_name}', methods=['POST'],content_types=['application/x-www-form-urlencoded','multipart/form-data'], authorizer=jwt_auth)
def s3objects(file_name):
    request = app.current_request
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    body = app.current_request.raw_body
    user.update_profile_pic(file_name,body)
    return {
        "uploaded": "true",
        "profile_pic_url": user.get_profile_pic(),
    }
@app.route('/me/profile_pic',#content_types=['application/octet-stream'],
methods=['GET'], authorizer=jwt_auth)
def getS3objects():
    request = app.current_request
    username = get_authorized_username(app.current_request)
    user = User.find(username)
    try:
        return {'image_url': user.get_profile_pic()}
    except ClientError as e:
        raise NotFoundError('image')

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
