# passeg
# Installation

## Switch to the root user
```sudo su -```

## Run the following commands to clone the repository and install dependancies
```cd /opt  
git clone https://github.com/mkaram007/passeg.git  
apt install python3  
apt install python3-pip  
apt-get install python3-venv
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


## Now open the browser and enter the following URL:  
  localhost:8000
