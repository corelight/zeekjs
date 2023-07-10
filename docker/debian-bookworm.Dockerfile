FROM debian:bookworm-slim

RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    g++ \
    gpg \
    libnode-dev \
    python3

ENV REPO_DISTRO=Debian_12

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/${REPO_DISTRO}/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/${REPO_DISTRO}/ /" | tee /etc/apt/sources.list.d/security:zeek.list && apt update

RUN apt install -y --no-install-recommends \
	zeek-btest \
	zeek-core \
	zeek-core-dev


ENV PATH=/opt/zeek/bin:$PATH

RUN btest --version
RUN zeek --version
RUN node --version

# Now compile, test and install the plugin
WORKDIR /src/
COPY . .
RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install
RUN zeek -N Zeek::JavaScript
RUN zeek ./examples/hello.js
