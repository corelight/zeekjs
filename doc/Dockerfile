FROM python:3.11@sha256:3df26df89a8935503d98a4a5a6430031760e8ba961fb75b85cb9d11696b34a3b

RUN apt-get update && apt-get install -y --no-install-recommends npm

WORKDIR /doc
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY package.json .
COPY package-lock.json .
RUN npm install


COPY . .
RUN make html
