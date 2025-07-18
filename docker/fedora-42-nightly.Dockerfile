FROM fedora:42

# Bust the cache
ARG STAMP=1741531139

# Dependencies required to compile and test ZeekJS on Fedora
RUN dnf install -y \
  cmake \
  diffutils \
  dnf-plugins-core \
  gcc-c++ \
  nodejs-devel \
  which \
  clang-tools-extra

# Ensure the sqlite-libs package is available to avoid:
# $ node --version
# node: symbol lookup error: /lib64/libnode.so.127: undefined symbol: sqlite3session_attach
RUN dnf update -y sqlite-libs

RUN dnf config-manager addrepo --from-repofile=https://download.opensuse.org/repositories/security:zeek/Fedora_42/security:zeek.repo

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
