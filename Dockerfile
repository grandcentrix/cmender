FROM debian:stable

# install deps
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    cmake \
    git \
    libcmocka-dev \
    libhttp-parser-dev \
    libmbedtls-dev \
    lcov
