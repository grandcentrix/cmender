# syntax=docker/dockerfile:1.6.0
FROM ubuntu:22.04 as build

# github action workflow step: Install dependencies
RUN <<EOF
    apt-get update
    # dependencies already installed in the github action ubuntu-latest base
    # image - we need to install them here separately
    apt-get install --no-install-recommends -y \
        ca-certificates \
        git \
        build-essential \
        cmake
    # dependencies from github action workflow
    apt-get install --no-install-recommends -y \
        clang-tools \
        libcmocka-dev \
        libhttp-parser-dev \
        libmbedtls-dev \
        lcov
    apt-get clean
    rm -rf /var/lib/apt/lists/*
EOF

WORKDIR /cmender
COPY CMakeLists.txt /cmender
COPY cmake cmake/
COPY include include/
COPY src src/
COPY platform platform/
COPY tests tests/

# github action workflow step: Install jsmn
RUN <<EOF
    git clone https://github.com/zserge/jsmn.git
    make -C jsmn
EOF
ENV CFLAGS="$CFLAGS -isystem /cmender/jsmn"
ENV LDFLAGS="$LDFLAGS -L/cmender/jsmn"

# github action workflow step: Compile
RUN <<EOF
    mkdir build
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTING=ON -DCODE_COVERAGE=ON
    make -C build
EOF

# github action workflow step: Test
RUN <<EOF
    make -C build test ARGS="-V"
    make -C build test_coverage
EOF

# minimal image with test_tool
FROM scratch
WORKDIR /lib64
COPY --from=build /lib64/ld-linux-x86-64.so.2 .
WORKDIR /lib/x86_64-linux-gnu
COPY --from=build /lib/x86_64-linux-gnu/libmbedtls.so.14 .
COPY --from=build /lib/x86_64-linux-gnu/libmbedcrypto.so.7 .
COPY --from=build /lib/x86_64-linux-gnu/libmbedx509.so.1 .
COPY --from=build /lib/x86_64-linux-gnu/libhttp_parser.so.2.9 .
COPY --from=build /lib/x86_64-linux-gnu/libcmocka.so.0 .
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 .
COPY --from=build /lib/x86_64-linux-gnu/librt.so.1 .
WORKDIR /
COPY --from=build /cmender/build/platform/linux/test_tool/test_tool .
ENTRYPOINT ["/test_tool"]
