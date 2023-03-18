FROM debian:bullseye

RUN apt update && apt install -y --no-install-recommends \
    curl \
    python3 \
    ca-certificates \
    gpg \
    g++ \
    build-essential \
    cmake

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' | tee /etc/apt/sources.list.d/security:zeek.list && apt update

RUN apt install -y --no-install-recommends \
	zeek-btest \
	zeek-core \
	zeek-core-dev

# Compile and install node as shared library
ENV NODE_VERSION=16.13.1
ENV NODE_SHA256=34b23965457fb08a8c62f81e8faf74ea60587cda6fa898e5d030211f5f374cb6
ENV NODE_FILENAME=node-v${NODE_VERSION}.tar.gz
ENV NODE_URL=https://nodejs.org/dist/v${NODE_VERSION}/${NODE_FILENAME}

WORKDIR /build/vendor
RUN curl -sSf -o node-v${NODE_VERSION}.tar.gz ${NODE_URL} && \
    echo "${NODE_SHA256} ${NODE_FILENAME}" | sha256sum --check && \
    tar xf ${NODE_FILENAME} && \
    cd node-v${NODE_VERSION} && \
    ./configure --prefix=/usr/local --shared --shared-openssl --shared-zlib && \
    make && \
    make install && \
    cd ../ && rm -rf node-v*

# Now compile, test and install the plugin
ENV PATH=/opt/zeek/bin:$PATH
WORKDIR /src/
COPY . .
RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install
RUN zeek -N Zeek::JavaScript
RUN zeek ./examples/hello.js
