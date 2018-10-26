import boto3
import os
import json
from application import *
class UserMailer(object):
    """docstring for UserMailer."""
    def __init__(self):
        super(UserMailer, self).__init__()
        self.mailer = ApplicationMailer()
        print('self.email_sender',self.mailer.email_sender)

    def send_confirmation_instruction(self, data):
        file_name = os.path.realpath('../views/user_mailer/send_confirmation_instruction.html.mako')
        print(file_name,'Real Path')
        self.mailer.send_mail(send_to=[data['username']],subject=None,bcc=[],cc=[],file_name=file_name,data=data)
        return data
