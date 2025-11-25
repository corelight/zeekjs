FROM fedora:43

# Dependencies required to compile and test ZeekJS on Fedora
RUN dnf install -y \
  cmake \
  diffutils \
  dnf-plugins-core \
  gcc-c++ \
  nodejs24-devel \
  which \
  clang-tools-extra

# Bust the cache
ARG STAMP=1763735680

RUN dnf config-manager addrepo --from-repofile=https://download.opensuse.org/repositories/security:zeek/Fedora_43/security:zeek.repo

RUN dnf install -y \
  zeek-btest \
  zeek-core \
  zeek-devel

ENV PATH=/opt/zeek/bin:$PATH

RUN btest --version
RUN zeek --version

# Run the build and compile
WORKDIR /src
COPY . .

RUN make check-clang-format

RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install

RUN zeek -N Zeek::JavaScript
RUN zeek ./examples/hello.js
