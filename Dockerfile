FROM ubuntu:18.04
FROM python:2

USER root
WORKDIR /root

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iputils-ping \
    mininet \
    net-tools \
    openvswitch-switch \
    openvswitch-testcontroller \
 && rm -rf /var/lib/apt/lists/* 
 
RUN pip install mininet
RUN pip install numpy


EXPOSE 6633 6653 6640

