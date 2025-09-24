FROM python:python:3.14.0rc1-alpine

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

CMD [ "python3", "./client.py"]
