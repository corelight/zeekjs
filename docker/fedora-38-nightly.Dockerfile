FROM fedora:38

# Dependencies required to compile and test ZeekJS on Fedora
RUN dnf install -y \
  cmake \
  diffutils \
  dnf-plugins-core \
  gcc-c++ \
  nodejs-devel \
  which \
  clang-tools-extra

# Bust the cache
ARG STAMP=1662210869

RUN dnf config-manager --add-repo https://download.opensuse.org/repositories/security:zeek/Fedora_37/security:zeek.repo

RUN dnf install -y \
  zeek-nightly-btest \
  zeek-nightly-core \
  zeek-nightly-devel

ENV PATH=/opt/zeek-nightly/bin:$PATH

RUN btest --version
RUN zeek --version

# Run the build and compile
WORKDIR /src
COPY . .

RUN make check-clang-format

RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install

RUN zeek -N Zeek::JavaScript
RUN zeek ./examples/hello.js
