FROM python:3
WORKDIR /opt
COPY ./app.py ./app.py
COPY ./lib/requirements.txt ./requirements.txt
COPY ./lib/main_settings.py ./lib/main_settings.py
RUN pip3 install -r requirements.txt
CMD ["python3", "./app.py"]
