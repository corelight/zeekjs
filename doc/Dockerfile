FROM python:3.9@sha256:f94a4c5a7289aaa06f7a2420a93b0e3f2fa734030a1d4d4e4421e663df1d9079

RUN apt-get update && apt-get install -y --no-install-recommends npm

WORKDIR /doc
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY package.json .
COPY package-lock.json .
RUN npm install


COPY . .
RUN make html
