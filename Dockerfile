FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    openssl libssl-dev \
    gdb \
    valgrind

# Create user and home directory
#RUN useradd -m -s /bin/bash corsair
WORKDIR /home/corsair
#USER corsair
