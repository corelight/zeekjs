#
# Convenience Makefile providing a few common top-level targets.
#
.PHONY: check
SHELL := /bin/bash
DOCKER ?= docker

cmake_build_dir=build
arch=`uname -s | tr A-Z a-z`-`uname -m`

all: build-it

build-it:
	@test -e $(cmake_build_dir)/config.status || ./configure
	-@test -e $(cmake_build_dir)/CMakeCache.txt && \
      test $(cmake_build_dir)/CMakeCache.txt -ot `cat $(cmake_build_dir)/CMakeCache.txt | grep ZEEK_DIST | cut -d '=' -f 2`/build/CMakeCache.txt && \
      echo Updating stale CMake cache && \
      touch $(cmake_build_dir)/CMakeCache.txt

	( cd $(cmake_build_dir) && make )

install:
	( cd $(cmake_build_dir) && make install )

clean:
	( cd $(cmake_build_dir) && make clean )

distclean:
	rm -rf $(cmake_build_dir)

test:
	make -C tests

format:
	clang-format -i ./src/*.{cc,h}

check-clang-format:
	clang-format -Werror --dry-run ./src/*.{cc,h}

check-clang-tidy: build-it
	clang-tidy -p ./build --extra-arg='-std=c++17' ./src/*{h,cc}

# Run format, build, tests and clang-tidy within a container.
check:
	$(DOCKER) build -t zeekjs-check -f ./docker/fedora-38.Dockerfile .

check-nightly:
	$(DOCKER) build --build-arg STAMP=$(shell date +%Y-%m-%d) -t zeekjs-check-nightly -f ./docker/fedora-38-nightly.Dockerfile .
