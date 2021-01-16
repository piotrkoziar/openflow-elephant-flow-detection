#!/bin/bash

rm piko_ryu_log.txt && \
ryu-manager src/controller.py \
--ofp-listen-host 127.0.0.1 \
--log-file ~/Documents/agh/openflow-elephant-flow-detection/piko_ryu_log.txt