import os 
SECRET_KEY = b'\xe1\x8dzK\xee\xeb\xb0\x86s\xd5\x014\xae2\xcaC'
SECURITY_PASSWORD_SALT = 'my_precious_two'


# mail settings
MAIL_DEFAULT_SENDER = "mohammedkaramtest0007@gmail.com"
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

os.environ["APP_MAIL_USERNAME"] = "mohammedkaramtest0007@gmail.com"
os.environ["APP_MAIL_PASSWORD"] = "zJ%kTJwE!K8H6.W["


# gmail authentication
MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

# mail accounts
MAIL_DEFAULT_SENDER = 'from@example.com'
