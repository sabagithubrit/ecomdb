# mail_password='ctft jocp tbpy spep'
import smtplib
from email.message import EmailMessage
def send_mail(to,subject,body):
    server=smtplib.SMTP_SSL('smtp.gmail.com',465)
    server.login('sabaparveenmd18@gmail.com','ctft jocp tbpy spep')
    msg=EmailMessage()
    msg['FROM']='sabaparveenmd18@gmail.com'
    msg['TO']=to
    msg['SUBJECT']=subject
    msg.set_content(body)
    server.send_message(msg)
    print('msg sent')
    server.close()