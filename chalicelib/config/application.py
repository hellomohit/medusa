from chalice import Chalice, AuthResponse, Response
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
from botocore.exceptions import ClientError
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
import pandas as pd
# from flask import Flask, render_template, request, redirect
import cgi
from io import BytesIO
#import secrets #P3
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
def _get_parts():
    rfile = BytesIO(app.current_request.raw_body)
    headers = app.current_request.headers
    content_type = app.current_request.headers['content-type']
    form = cgi.FieldStorage(fp=rfile, environ={'REQUEST_METHOD': 'POST'},headers={
            'content-type': content_type,
        },keep_blank_values=True)
    return form
