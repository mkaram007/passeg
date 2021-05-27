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
  
# To test the requests:
   Considering testing on a vm with IP address 165.227.235.228  
   and running the application on port 8000   
   ssh on the vm from a linux machine using the following command:  
   ```ssh root@165.227.235.228 -L 8000:localhost:8000```  
   enter the password  
   
# Now follow the following steps:  

## 1-Open postman application:  
   You can download postman application for linux here:  
   https://dl-agent.pstmn.io/download/latest/linux  
   For windows:  
   https://dl-agent.pstmn.io/download/latest/win64  
   For Mac:  
   https://dl-agent.pstmn.io/download/latest/osx  
   
## 2-Click on the import button:  
   Click upload files, choose the file named:  
   ```passeg.postman_collection.json```  
   
## 3-Start by signing up:  
   -Choose the /signup request from the collection  
   -Click on the body tab  
   -Choose whatever name, username and password you want  
   -Click send  
   -You should get the following response:  
    ```{
    "data": "Registeration completed with ID: 1",
    "status": "success"
   }```  
   -That means you're successfully signed up  
   
## 4-Now you can login 
   Using the /login request in the same way by opening the body tab, enter your credentials and click send
   
## 5-For any question, please contact the developer


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
## 14-Current requests (Found in the postman collection file):  
1-/signup  
2-/login  
3-/getPassword/<PASSWORD_ID>  
4-/addPassword  
5-/updatePassword/<PASSWORD_ID>  
6-/getPasswordId/<PASSWORD_USERNAME>  
7-/deletePassword/<PASSWORD_ID>  
8-/generateRandomPassword  
9-/logout  
10-/getCurrentUser  
11-/updateUser/<USERNAME>  
12-/getPasswords  
13-/sharePasswordWith/<PASSWORD_ID>/<USER_ID>  
14-/makePasswordOwner/<PASSWORD_ID>/<USER_ID>  
15-/revokePasswordShare/<PASSWORD_ID>/<USER_ID>  
16-/revokePasswordOwner/<PASSWORD_ID>/<USER_ID>  
17-/createGroup  
18-/addUserToGroup/<USER_ID>/<GROUP_ID>  
19-/addPasswordToGroup/<PASSWORD_ID>/<GROUP_ID>  
20-/makeGroupManager/<USER_ID>/<GROUP_ID>  
21-/makeGroupOwner/<USER_ID>/<GROUP_ID>
   
   

   
