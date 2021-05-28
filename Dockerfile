FROM python:3
COPY ./app.py ./app.py
COPY ./lib/requirements.txt ./requirements.txt
COPY ./lib/main_settings.py ./lib/main_settings.py
RUN pip3 install -r requirements.txt
EXPOSE 8000
CMD ["python3", "./app.py"]
