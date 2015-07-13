#!/usr/bin/env python

"""Local network discovery inventory script

Generates an Ansible inventory of all hosts on a local network that
appear to be capable of incoming SSh connections (i.e. have port 22
open).
"""

import argparse
import json
import nmap
import socket
import time

class LocalNetworkInventory(object):
  def __init__(self):
    """Main execution path"""
    self.parse_cli_args()

    data_to_print = ""

    if self.args.host:
      data_to_print = self.get_host_info()
    else:
      # Default action is to list instances, so we don't bother
      # checking `self.args.list`.
      data_to_print = self.json_format_dict(self.get_inventory())

    print data_to_print


  def parse_cli_args(self):
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
      description="Produce an Ansible Inventory file comprised of hosts on the local network"
    )
    parser.add_argument(
      "--list",
      action="store_true",
      default=True,
      help="List instances (default: True)"
    )
    parser.add_argument(
      "--host",
      action="store",
      help="Get all the variables about a specific instance"
    )
    parser.add_argument(
      "--connect-address",
      metavar="ADDR",
      action="store",
      default="whiskerlabs.com",
      help="A hostname or IP address to use in determining localhost's public IP"
    )
    self.args = parser.parse_args()


  def get_inventory(self):
    """Populate `self.inventory` with hosts on the local network that
    are accessible via SSH.
    """
    return { "all": { "hosts": self.lookup_local_ips() }}


  def json_format_dict(self, data):
    return json.dumps(data, sort_keys=True, indent=2)


  def get_local_routing_prefix(self):
    """Computes the local network routing prefix in CIDR notation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((self.args.connect_address, 80))
    localhost_ip = sock.getsockname()[0]
    sock.close()
    octet_strs = localhost_ip.split('.')[:3]
    octet_strs.append('0')
    return '.'.join(octet_strs) + "/24"


  def lookup_local_ips(self):
    """Lookup IPs of hosts connected to the local network"""
    nm = nmap.PortScanner()
    nm.scan(hosts=self.get_local_routing_prefix(), arguments="-p 22 --open")
    return nm.all_hosts()


  def get_host_info(self):
    """Get variables about a specific host"""
    return self.json_format_dict({})


LocalNetworkInventory()
