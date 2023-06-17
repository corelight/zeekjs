FROM python:3.11@sha256:6b85854518f812d94cf2dfee2386df85b9cb78835a872d4769b4335f584c43ba

RUN apt-get update && apt-get install -y --no-install-recommends npm

WORKDIR /doc
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY package.json .
COPY package-lock.json .
RUN npm install


COPY . .
RUN make html
