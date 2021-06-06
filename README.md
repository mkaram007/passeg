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

# There are two methods of installing passeg:

# Method 1: With docker
## Install docker:
``` sudo curl https://get.docker.com | bash ```

## Start docker service and make sure it’s active and running.
``` sudo systemctl start docker.service```
```sudo systemctl status docker.service```

## It should provide a result like this:
```
● docker.service - Docker Application Container Engine
     Loaded: loaded (/lib/systemd/system/docker.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/docker.service.d
             └─override.conf
     Active: active (running) since Wed 2021-06-02 02:42:23 UTC; 4 days ago
TriggeredBy: ● docker.socket
       Docs: https://docs.docker.com
   Main PID: 157751 (dockerd)
      Tasks: 24
     Memory: 159.3M
     CGroup: /system.slice/docker.service
             ├─157751 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
             ├─245719 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8000 -container-ip 172.18.0.2 -container-port 8000
             └─245725 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8000 -container-ip 172.18.0.2 -container-port 8000
             
 ```
## Run this command to add your user to the docker group, replace \<Username> with your username
``` sudo usermod -aG docker <Username> ```

## logout from the user and login again to apply the docker group permissions


## Install docker-compose using the following commands:
``` sudo curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose ```

## Apply executable permissions to the binary:
```sudo chmod +x /usr/local/bin/docker-compose```

## To start with the docker image build process, run the following commands:
``` cd /opt/passeg ```
``` docker-compose build ```
``` docker-compose run -d ```

# Now passeg should be working, you can move to the "To test the requests" step below
   
# Method 2: without docker

## Create your virtual environment
```
python3 -m venv venv  
source venv/bin/activate  
```

## Run the following command to install the python requirements:
```
/opt/passeg/venv/bin/pip3 install -r /opt/passeg/lib/requirements.txt  
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

# Now passeg should be working
  
# To test the requests:
   Considering testing on a vm with IP address 1.2.3.4  
   and running the application on port 8000   
   ssh on the vm from a linux machine using the following command:  
   ```ssh root@1.2.3.4 -L 8000:localhost:8000```  
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
14-Group feature  
15-Encryption and decryption of the stored password  
16-Hashing user password
17-Creating Dockerfile for passeg
18-Creating docker-compose file for passeg
19-Working on strenghtening the security system of passeg

## Current requests (Found in the postman collection file):  
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
22-/deleteMemberFromGroup/<USER_ID>/<GROUP_ID>  
23-/changeUserPassword  
24-/changeRecordPassword/<RECORD_ID>  
25-/revokeManagerOfGroup/<MANAGER_ID>/<GROUP_ID>  
26-/revokeOwnerOfGroup/<OWNER_ID>/<GROUP_ID>  
27-/deletePasswordFromGroup/<PASSWORD_ID>/<GROUP_ID>  
28-/deleteGroup/<GROUP_ID>
