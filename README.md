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

## Create your own virtual environment
```
cd passeg
rm -rf venv
python3 -m venv venv
```

## Install the requirements
```
venv/bin/pip3 install -r lib/requirements.txt
```

## Return back to your user
Press CTRL + D

## Add the passeg service  
```sudo cp passeg/passeg.service /lib/systemd/system/passeg.service  ```

## Restart the system daemon  
```sudo systemctl daemon-reload  ```


## Run passeg service
```sudo systemctl start passeg  ```

## Make it start whenever the system starts
```sudo systemctl enable passeg  ```


## Now open the browser and enter the following URL (If passeg has been installed on your local machine):  
  localhost:8000



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
14-Working on email confirmation  
