#!/bin/sh

build() {
    rm -rf build
    mkdir build
    cd build

    git clone https://github.com/zserge/jsmn.git
    make -C jsmn
    export CFLAGS="$CFLAGS -I$(pwd)/jsmn"
    export LDFLAGS="$LDFLAGS -L$(pwd)/jsmn"

    cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTING=ON -DCODE_COVERAGE=ON ..
    make
}

test() {
    cd build
    make test ARGS="-V"
    make test_coverage
}

"$1"
