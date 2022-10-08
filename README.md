# passman
# Installation

## Switch to the root user
```sudo su -```

## Run the following commands to clone the repository and install dependancies
```cd /opt  
git clone https://github.com/mkaram007/passman.git  
apt install python3  
apt install python3-pip  
apt-get install python3-venv
```
## Return back to your user
Press CTRL + D

## Add the passman service  
```sudo cp passman/passman.service /lib/systemd/system/passman.service  ```

## Restart the system daemon  
```sudo systemctl daemon-reload  ```


## Run passman service
```sudo systemctl start passman  ```

## Make it start whenever the system starts
```sudo systemctl enable passman  ```


## Now open the browser and enter the following URL:  
  localhost:8000
