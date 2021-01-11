#!/bin/bash

docker image rm ssp_container
docker build -t ssp_container .
