import boto3
import os
import json
import getpass
import argparse
import hashlib
import hmac
import uuid
import datetime
from boto3.dynamodb.types import Binary
S3 = boto3.client('s3', region_name='ap-south-1')
USER_BUCKET = 'medusa-user-profile-pic'
# from mailer.user_mailer import UserMailer
class User(object):
    """docstring for User."""
    def __init__(self,args={}):
        super(User, self).__init__()
        if 'password' in args:
            password = args['password']
            password_fields = self.encode_password(password)
            args['hash'] = password_fields['hash']
            args['salt'] = Binary(password_fields['salt'])
            args['rounds'] = password_fields['rounds']
            args['hashed'] = Binary(password_fields['hashed'])
        self.uid = args['uid'] if('uid' in args) else str(uuid.uuid4())
        self.profile_pic_url = args['profile_pic_url'] if('profile_pic_url' in args) else None
        self.name = args['name'] if('name' in args) else None
        self.gender = args['gender'] if('gender' in args) else None
        self.club = args['club'] if('club' in args) else None
        self.is_coach = args['is_coach'] if('is_coach' in args) else False
        self.is_admin = args['is_admin'] if('is_admin' in args) else False
        self.username = args['username'] if('username' in args) else None
        self.hash = args['hash'] if('hash' in args) else None#password_fields['hash']
        self.salt = args['salt'] if('salt' in args) else None#Binary(password_fields['salt'])
        self.rounds = args['rounds'] if('rounds' in args) else None#password_fields['rounds']
        self.hashed = args['hashed'] if('hashed' in args) else None#Binary(password_fields['hashed'])
        self.confirmation_token = args['confirmation_token'] if('confirmation_token' in args) else str(uuid.uuid4())
        self.confirmed_at = args['confirmed_at'] if('confirmed_at' in args) else None
        self.reset_password_token = args['reset_password_token'] if('reset_password_token' in args) else None
        self.reset_password_sent_at = args['reset_password_sent_at'] if('reset_password_sent_at' in args) else None
        self.remember_created_at = args['remember_created_at'] if('remember_created_at' in args) else None
        self.sign_in_count = args['sign_in_count'] if('sign_in_count' in args) else 0
        self.current_sign_in_at = args['current_sign_in_at'] if('current_sign_in_at' in args) else None
        self.last_sign_in_at = args['last_sign_in_at'] if('last_sign_in_at' in args) else None
        self.current_sign_in_ip = args['current_sign_in_ip'] if('current_sign_in_ip' in args) else None
        self.last_sign_in_ip = args['last_sign_in_ip'] if('last_sign_in_ip' in args) else None
        self.confirmation_sent_at = args['confirmation_sent_at'] if('confirmation_sent_at' in args) else None
        self.unconfirmed_email = args['unconfirmed_email'] if('unconfirmed_email' in args) else None
        self.failed_attempts = args['failed_attempts'] if('failed_attempts' in args) else 0
        self.unlock_token = args['unlock_token'] if('unlock_token' in args) else None
        self.locked_at = args['locked_at'] if('locked_at' in args) else None
        self.created_at = args['created_at'] if('created_at' in args) else str(datetime.datetime.now())
        self.update_at = args['update_at'] if('update_at' in args) else str(datetime.datetime.now())
    def attributes(self):
        item = {
            'uid': self.uid,
            'name': self.name,
            'gender': self.gender,
            'club': self.club,
            'is_coach': self.is_coach,
            'is_admin': self.is_admin,
            'username': self.username,
            'profile_pic_url': self.profile_pic_url,
            # 'hash': self.hash,
            # 'salt': self.salt,
            # 'rounds': self.rounds,
            # 'hashed': self.hashed,
            'confirmation_token': self.confirmation_token,
            'confirmed_at': self.confirmed_at,
            'reset_password_token': self.reset_password_token,
            'reset_password_sent_at': self.reset_password_sent_at,
            'remember_created_at': self.remember_created_at,
            'sign_in_count': self.sign_in_count,
            'current_sign_in_at': self.current_sign_in_at,
            'last_sign_in_at': self.last_sign_in_at,
            'current_sign_in_ip': self.current_sign_in_ip,
            'last_sign_in_ip': self.last_sign_in_ip,
            'confirmation_sent_at': self.confirmation_sent_at,
            'unconfirmed_email': self.unconfirmed_email,
            'failed_attempts': self.failed_attempts,
            'unlock_token': self.unlock_token,
            'locked_at': self.locked_at,
            'created_at': self.created_at,
            'update_at': self.update_at,
        }
        return item
    @classmethod
    def find(self,username):
        user_detail = User.get_users_db().get_item(
            Key={'username': username})
        if 'Item' in user_detail:
            user = User()
            user.assign_attributes(user_detail['Item'])
            return user
        else:
            return None
    def update_profile_pic(self,file_name,body):
        # write body to tmp file
        tmp_file_name = '/tmp/' + file_name
        with open(tmp_file_name, 'wb') as tmp_file:
            tmp_file.write(body)
        # upload tmp file to s3 bucket
        self.profile_pic_url = (self.pic_key() +'/' + file_name)
        S3.upload_file(tmp_file_name, USER_BUCKET, self.profile_pic_url)
        self.save()
        return self.profile_pic_url
    def pic_key(self):
        return 'UserProfilePic' + self.uid
    def get_profile_pic(self):
        # bucket_location = boto3.client('s3').get_bucket_location(Bucket=USER_BUCKET)
        return S3.generate_presigned_url(
                ClientMethod='get_object',
                Params={
                    'Bucket': USER_BUCKET,
                    'Key': self.profile_pic_url
                }
            )
        # return S3.get_object(Bucket=USER_BUCKET, Key=self.profile_pic_url)
    def update_attributes(self,item_json):
        table_name = self.get_table_name()
        table = boto3.resource('dynamodb').Table(table_name)
        # item_json['update_at'] = str(datetime.datetime.now())
        item = self.attributes()
        item.update(item_json)
        print(item_json)
        response = table.update_item(
            Key={'username': self.username},
            AttributeUpdates = self.prepare_update_data(item_json),
        )
        print(response)
        self.assign_attributes(item)
        return self.attributes()

    def prepare_update_data(self,item):
        data = {}
        for key,val in item.items():
            if key in self.allowed_attributes():
                data[key] = {'Value': val,'Action': 'PUT'}
        return data
    def allowed_attributes(self):
        return ['name','gender','club']
    def assign_attributes(self,item):
        self.uid = item['uid'] if('uid' in item) else str(uuid.uuid4())
        self.profile_pic_url = item['profile_pic_url'] if('profile_pic_url' in item) else None
        self.name = item['name'] if('name' in item) else None
        self.gender = item['gender'] if('gender' in item) else None
        self.club = item['club'] if('club' in item) else None
        self.is_coach = item['is_coach'] if('is_coach' in item) else False
        self.is_admin = item['is_admin'] if('is_admin' in item) else False
        self.username = item['username'] if('username' in item) else None
        self.hash = item['hash'] if('hash' in item) else None#password_fields['hash']
        self.salt = item['salt'] if('salt' in item) else None#Binary(password_fields['salt'])
        self.rounds = item['rounds'] if('rounds' in item) else None#password_fields['rounds']
        self.hashed = item['hashed'] if('hashed' in item) else None#Binary(password_fields['hashed'])
        self.confirmation_token = item['confirmation_token'] if('confirmation_token' in item) else str(uuid.uuid4())
        self.confirmed_at = item['confirmed_at'] if('confirmed_at' in item) else None
        self.reset_password_token = item['reset_password_token'] if('reset_password_token' in item) else None
        self.reset_password_sent_at = item['reset_password_sent_at'] if('reset_password_sent_at' in item) else None
        self.remember_created_at = item['remember_created_at'] if('remember_created_at' in item) else None
        self.sign_in_count = item['sign_in_count'] if('sign_in_count' in item) else 0
        self.current_sign_in_at = item['current_sign_in_at'] if('current_sign_in_at' in item) else None
        self.last_sign_in_at = item['last_sign_in_at'] if('last_sign_in_at' in item) else None
        self.current_sign_in_ip = item['current_sign_in_ip'] if('current_sign_in_ip' in item) else None
        self.last_sign_in_ip = item['last_sign_in_ip'] if('last_sign_in_ip' in item) else None
        self.confirmation_sent_at = item['confirmation_sent_at'] if('confirmation_sent_at' in item) else None
        self.unconfirmed_email = item['unconfirmed_email'] if('unconfirmed_email' in item) else None
        self.failed_attempts = item['failed_attempts'] if('failed_attempts' in item) else 0
        self.unlock_token = item['unlock_token'] if('unlock_token' in item) else None
        self.locked_at = item['locked_at'] if('locked_at' in item) else None
        self.created_at = item['created_at'] if('created_at' in item) else str(datetime.datetime.now())
        self.update_at = item['update_at'] if('update_at' in item) else str(datetime.datetime.now())
    def get_table_name(self):
        # We might want to user the chalice modules to
        # load the config.  For now we'll just load it directly.
        return os.environ['USERS_TABLE_NAME']


    def save(self):
        table_name = self.get_table_name()
        table = boto3.resource('dynamodb').Table(table_name)
        self.update_at = str(datetime.datetime.now())
        item = self.attributes()
        item['hash'] = self.hash
        item['salt'] = self.salt
        item['rounds'] = self.rounds
        item['hashed'] = self.hashed
        table.put_item(Item=item)
    def update(self):
        self.save()

    def encode_password(self,password, salt=None):
        if salt is None:
            self.salt = os.urandom(16)
        self.rounds = 100000
        self.hashed = hashlib.pbkdf2_hmac('sha256', password, self.salt, self.rounds)
        return {
            'hash': 'sha256',
            'salt': self.salt,
            'rounds': self.rounds,
            'hashed': self.hashed,
        }

    def list_users(self):
        table_name = self.get_table_name()
        table = boto3.resource('dynamodb').Table(table_name)
        for item in table.scan()['Items']:
            print(item['username'])

    def test_password(self,password):
        username = self.username
        table_name = self.get_table_name()
        table = boto3.resource('dynamodb').Table(table_name)
        item = table.get_item(Key={'username': username})['Item']
        encoded = encode_password(password, salt=item['salt'].value)
        if hmac.compare_digest(encoded['hashed'], item['hashed'].value):
            print("Password verified.")
        else:
            print("Password verification failed.")

    @classmethod
    def get_users_db(self):
        _USER_DB = boto3.resource('dynamodb').Table(
            os.environ['USERS_TABLE_NAME'])
        return _USER_DB
