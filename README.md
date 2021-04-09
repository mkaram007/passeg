# passeg
## Installation
cd  
git clone https://github.com/mkaram007/passeg.git  
sudo apt install python3  
sudo apt install python3-pip  
pip3 install virtualenv  
cd passeg  
## Will work on a generic virtual environment:
rm -rf venv  
python3 -m venv venv  
source venv/bin/activate  
## Run the following command to install the python requirements:
~/passeg/venv/bin/pip3 install -r ~/passeg/lib/requirements.txt
## Run the server using the following command:
python3 app.py  
## Open the browser and enter the following URL:  
  localhost:8000  
