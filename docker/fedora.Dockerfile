FROM fedora:35

# Dependencies required to compile and test ZeekJS on Fedora
RUN dnf install -y \
  cmake \
  diffutils \
  dnf-plugins-core \
  gcc-c++ \
  gdb \
  nodejs-devel \
  v8-devel \
  which \
  clang-tools-extra

RUN dnf config-manager --add-repo https://download.opensuse.org/repositories/security:zeek/Fedora_34/security:zeek.repo

RUN dnf install -y \
  zeek-btest \
  zeek-core \
  zeek-devel

ENV PATH=/opt/zeek/bin:$PATH

# Run the build and compile
WORKDIR /src
COPY . .

RUN make check-clang-format

RUN rm -rf build && ./configure && make && ( cd tests && btest -A -d -c btest.cfg ) && make install

# Run clang-tidy now - this may take a while.
WORKDIR /src
RUN make check-clang-tidy

RUN zeek -N Corelight::ZeekJS
RUN zeek ./examples/hello.js
