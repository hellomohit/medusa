from chalice import Chalice, AuthResponse
from chalicelib import auth, db
from chalice import UnauthorizedError
from chalice import NotFoundError
from chalice import BadRequestError
from chalice import ForbiddenError
from chalice import ConflictError
from chalice import UnprocessableEntityError
from chalice import TooManyRequestsError
from chalice import ChaliceViewError
import boto3
import os
import json
import getpass
import argparse
import hashlib
import hmac
import uuid
import datetime
import decimal
from boto3.dynamodb.types import Binary
from chalicelib.models.user import User
import pandas as pd
# from django.core.serializers.json import DjangoJSONEncoder
# from django.core.serializers import serialize
#import secrets
# * BadRequestError - return a status code of 400
# * UnauthorizedError - return a status code of 401
# * ForbiddenError - return a status code of 403
# * NotFoundError - return a status code of 404
# * ConflictError - return a status code of 409
# * UnprocessableEntityError - return a status code of 422
# * TooManyRequestsError - return a status code of 429
# * ChaliceViewError - return a status code of 500

app = Chalice(app_name='coach')

app.debug = True
_DB = None
#boto3.resource('dynamodb').Table(os.environ['APP_TABLE_NAME'])
_USER_DB = None
#boto3.resource('dynamodb').Table(os.environ['USERS_TABLE_NAME'])

@app.route('/')
def index():
    return {'hello': 'world'}


# The view function above will return {"hello": "world"}
# whenever you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
@app.route('/hello/{name}')
def hello_name(name):
   # '/hello/james' -> {"hello": "james"}
   return {'hello': name}

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
        password = user_as_json['password']
        password_fields = encode_password(password)
        item = {
            'name': None,
            'gender': None,
            'club': None,
            'is_coach': False,
            'is_admin': False,
            'username': username,
            'hash': password_fields['hash'],
            'salt': Binary(password_fields['salt']),
            'rounds': password_fields['rounds'],
            'hashed': Binary(password_fields['hashed']),
            'confirmation_token': str(uuid.uuid4()),
            'confirmed_at': None,
            'reset_password_token': None,
            'reset_password_sent_at': None,
            'remember_created_at': None,
            'sign_in_count': 0,
            'current_sign_in_at': None,
            'last_sign_in_at': None,
            'current_sign_in_ip': None,
            'last_sign_in_ip': None,
            'confirmation_sent_at': None,
            'unconfirmed_email': None,
            'failed_attempts': 0,
            'unlock_token': None,
            'locked_at': None,
            'created_at': str(datetime.datetime.now()),
            'update_at': str(datetime.datetime.now()),
        }
        table.put_item(Item=item)
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
