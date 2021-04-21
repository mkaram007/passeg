# passeg
## Installation
sudo su -  
cd /opt  
git clone https://github.com/mkaram007/passeg.git  
apt install python3  
apt install python3-pip  
apt-get install python3-venv



## Add the passeg service  
sudo cp passeg/passeg.service /lib/systemd/system/passeg.service  

## Restart the system daemon  
sudo systemctl daemon-reload  


## Run passeg service
sudo systemctl start passeg  

## Make it start whenever the system starts
sudo systemctl enable passeg  


## Open the browser and enter the following URL:  
  localhost:8000
