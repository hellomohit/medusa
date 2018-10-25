import boto3
import os
import json
from mako.template import Template
from mako.lookup import TemplateLookup
EMAIL_SENDER = 'hello@coach.com'
class ApplicationMailer(object):
    """docstring for ApplicationMailer."""
    def __init__(self, email_sender=None):
        super(ApplicationMailer, self).__init__()
        if email_sender == None:
            self.email_sender = EMAIL_SENDER
        else:
            self.email_sender = email_sender

    def send_mail(self,send_to=[],subject=None,bcc=[],cc=[],file_name=None,directories=None,data={}):
        client = boto3.client('ses')
        # response = client.send_email(
        #     Source='string',
        #     Destination={
        #         'ToAddresses': send_to,
        #         'CcAddresses': cc,
        #         'BccAddresses': bcc
        #     },
        #     Message={
        #         'Subject': {
        #             'Data': subject,
        #             'Charset': 'UTF-8'
        #         },
        #         'Body': {
        #             'Html': {
        #                 'Data': mail_render(directories=directories,file_name=file_name),
        #                 'Charset': 'UTF-8'
        #             }
        #         }
        #     }
        # )
        return self.mail_render(directories=directories,file_name=file_name,data=data)

    def mail_render(self,directories=['../views/user_mailer'],file_name=None,data={}):
        # mylookup = TemplateLookup(directories=directories, output_encoding='UTF-8', encoding_errors='replace')
        # mytemplate = mylookup.get_template(file_name)
        # return mytemplate.render()
        filename = file_name
        mytemplate = Template(filename=file_name, module_directory='../modules/mako_modules')
        return (mytemplate.render(data))
