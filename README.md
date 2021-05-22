# passeg
# Installation

## Switch to the root user
```sudo su -```  

## Update your system packages
```apt update ```  
```apt upgrade ```
## Run the following commands to clone the repository and install dependancies
```  
cd /opt  
git clone https://github.com/mkaram007/passeg.git  
apt install python3  
apt install python3-pip  
apt-get install python3-venv
```

## Return back to your user
Press CTRL + D

## Add the passeg service  
```sudo cp /opt/passeg/passeg.service /lib/systemd/system/passeg.service  ```

## Restart the system daemon  
```sudo systemctl daemon-reload  ```


## Run passeg service
```sudo systemctl start passeg  ```

## Make it start whenever the system starts
```sudo systemctl enable passeg  ```

## Make sure it's working without an error
``` sudo systemctl status passeg ```

You should get this sample output

```
● passeg.service - Password manager service
   Loaded: loaded (/lib/systemd/system/passeg.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2021-05-19 08:20:17 UTC; 3s ago
 Main PID: 12853 (python3)
    Tasks: 3 (limit: 1152)
   CGroup: /system.slice/passeg.service
           ├─12853 /opt/passeg/venv/bin/python3 /opt/passeg/app.py
           └─12876 /opt/passeg/venv/bin/python3 /opt/passeg/app.py

May 19 08:20:18 ubuntu-bionic python3[12853]:    Use a production WSGI server instead.
May 19 08:20:18 ubuntu-bionic python3[12853]:  * Debug mode: on
May 19 08:20:18 ubuntu-bionic python3[12853]: /opt/passeg/venv/lib/python3.6/site-packages/flask_sqlalchemy/__in
May 19 08:20:18 ubuntu-bionic python3[12853]:   'SQLALCHEMY_TRACK_MODIFICATIONS adds significant overhead and '
May 19 08:20:18 ubuntu-bionic python3[12853]:  * Running on http://127.0.0.1:8000/ (Press CTRL+C to quit)
May 19 08:20:18 ubuntu-bionic python3[12853]:  * Restarting with stat
May 19 08:20:20 ubuntu-bionic python3[12853]: /opt/passeg/venv/lib/python3.6/site-packages/flask_sqlalchemy/__in
May 19 08:20:20 ubuntu-bionic python3[12853]:   'SQLALCHEMY_TRACK_MODIFICATIONS adds significant overhead and '
May 19 08:20:20 ubuntu-bionic python3[12853]:  * Debugger is active!
May 19 08:20:20 ubuntu-bionic python3[12853]:  * Debugger PIN: 272-630-519


```

## Now open the browser and enter the following URL (If passeg has been installed on your local machine):  
  localhost:8000  
  You should get a "Method Not Allowed" Message, don't worry that means it's working correctly
  



# Progress steps in passeg project:
1-Sign up functionality  
2-User authentication functionality (login, logout)  
3-Restricting pages access without login  
4-Add password records  
5-Update password details  
6-Delete password record  
7-Random password generation for a record  
8-Password details page  
9-Alerts when an error arises  
10-Separating each user's data (Password records)  
11-Navigation bar  
12-Password copy button  
13-e-mail validation  
## 14-Current requests:  
1-Signup  
2-Login  
3-Get Password details  
4-Add a password  
5-Update a password  
6-Get password id  
7-Delete a password  
8-Get a random password  
9-Logout  
10-Get current user id  
11-Edit user details  
12-Get all passwords for a user
