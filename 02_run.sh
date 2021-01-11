#!/bin/bash

docker run -it --rm --network host --privileged -v "$PWD"/src/:/root ssp_4 python2 mininet_runner.py



