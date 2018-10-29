#### Install packages
$ pip install -r requirements.txt --user

#### Start local server
$ chalice local

#### Generate Model
$ python g.py --model User

#### Create Users table and save it to config.json
$ python db.py --table-type users --stage dev

#### Create App table and save it to config.json
$ python db.py --table-type app --stage dev

#### Create a test user:
$ python users.py --create-user
Username: myusername
Password:

#### To test that password verification works:
$ python users.py -t
Username: myusername
Password:
Password verified.

#### Deploy the code
$ chalice deploy
