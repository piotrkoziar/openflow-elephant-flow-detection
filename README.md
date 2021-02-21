# openflow-elephant-flow-detection

This project implements OpenFlow controller that detects and reacts to elephant flows.

For incoming packets, the controller installs flows based on defined paths (see path_manager.py) and packet attributes.

### Paths

Path is a list of port pairs (in port and out port) for given switches (datapath IDs).
Flows are installed to match the path in both directions.

Path manager allows to retrieve two types of paths: base and alternative.
Each alternative path has its base path.

When packet arrives to packet_in handler, the base path is applied by the installed flows.

### Packet attributes

IPv6 and LLDP packets are ignored.

The controller installs defined flows for the ethernet packet types:
- ARP
- IPv4
    - ICMP
    - UDP
    - TCP

If a packet arrives with any type not specified above, the controller acts like learning switch (creates flow based on the in port and destination).

Set of attributes that is put to flow's match structure depends on the packet type. For example, for UDP there will be ports and IP addresses and for ICMP there will be only IP addresses.

### Elephant handling

A monitor thread is spawned to update statistics of the flows.
Throughput is calculated there.
If any flow has its throughput greater than threshold, it is marked as elephant.
For detected elephant flow, the controller do the following:
1. Looks for its base path.
2. Obtains one of the alternative paths related with the base path.
3. Applies the alternative path (flows are installed) that has higher priority and is temporary (created flows have timeouts).

## Content:

mininet_runner.py - creates simple network in mininet.
flows_generator.py - generates traffic with iperf.
controller.py - event handler. Uses interface of flow manager.
flow_manager.py - creates, deletes, updates, saves flows. Applies paths. Also detects elephant flows and reacts to them by installing higher-priority flows.
flow.py - represents the flow and implements base functionality (such as flow comparison).
path_manager.py - imports defined paths and exposes methods to obtain base and alternative paths.
## RUN:

To run project, do the following:

1. Run `sudo python src/mininet_runner.py`
2. `./run_ryu.sh`

Logs are saved to piko_ryu_log.txt file.

## Additional notes:

Tested with Python version 2.7.17 and mininet version 2.2.2.