FROM ubuntu:22.10

RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    g++ \
    gpg \
    libnode-dev \
    python3

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.10/ /' | tee /etc/apt/sources.list.d/security:zeek.list
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.10/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

RUN apt-get update && apt-get install -y --no-install-recommends \
	zeek-btest \
	zeek-core \
	zeek-core-dev


ENV PATH=/opt/zeek/bin:$PATH

# Now compile, test and install the plugin
WORKDIR /src/
COPY . .
RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install
RUN zeek -N Corelight::ZeekJS
RUN zeek ./examples/hello.js
