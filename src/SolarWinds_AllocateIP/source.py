"""
Copyright (c) 2022 Aleksandr Istomin, https://as.zabedu.ru

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from orionsdk import SwisClient
from vra_ipam_utils.ipam import IPAM


def handler(context, inputs):
    """
    Create IPAM object and start allocation function
    """
    ipam = IPAM(context, inputs)
    IPAM.do_allocate_ip = do_allocate_ip
    return ipam.allocate_ip()


def do_allocate_ip(self, auth_credentials, _):
    """
    Main function.
    Get inputs,
    create connection with IPAM server,
    execute operation and
    prepare results
    """
    custom_ip_address = "none"
    try:
        custom_ip_address = self.inputs["ipAllocations"][0]["start"]
        if custom_ip_address != "none":
            logging.info("IP set manually: %s", custom_ip_address)
    except Exception:
        logging.info("No custom IP address")
    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    ignore_ssl_warning = self.inputs["endpoint"]["endpointProperties"] \
                                  ["ignoreSslWarning"].lower() == "true"
    if ignore_ssl_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    swis = SwisClient(self.inputs["endpoint"]["endpointProperties"] \
                                 ["hostName"], username, password, self.inputs["endpoint"]["endpointProperties"]["apiPort"])
    allocation_result = []
    try:
        for allocation in self.inputs["ipAllocations"]:
            allocation_result.append(allocate(swis, allocation, custom_ip_address))
    except Exception as error:
        try:
            rollback(swis, allocation_result)
        except Exception as rollback_e:
            logging.error("Error in IP deallocation %s", str(allocation_result))
            logging.error(rollback_e)
        raise error

    assert len(allocation_result) > 0
    return {
        "ipAllocations": allocation_result
    }


def allocate(swis, allocation, ip):
    """
    Get one free IP address and prepare sesult
    """
    last_error = None
    for range_id in allocation["ipRangeIds"]:
        logging.info("Allocating IP from range %s", range_id)
        try:
            if ip is not None and ip != "none":
                ip_addresses = get_free_ips(swis, get_subnet_id(range_id))
                if ip in ip_addresses:
                    ip_address = ip
                else:
                    ip_address = None
                    logging.info("IP %s was not found in the list of free IP addresses", ip)
            else:
                ip_address = get_free_ip(swis, range_id)
            if ip_address is not None:
                result = {
                    "ipAllocationId": allocation["id"],
                    "ipRangeId": range_id,
                    "ipVersion": "IPv4",
                    "ipAddresses": [ip_address]
                }
                change_ip_status(swis, ip_address, "Used")
                return result
            else:
                raise Exception("No free IPs found")
        except Exception as error:
            last_error = error
            logging.error("Failed to allocate IP in %s: %s", range_id, str(error))

    logging.error("No more ranges. Raising last error")
    raise last_error


def rollback(swis, allocation_result):
    """
    Rollback any previously allocated addresses
    in case this allocation request
    contains multiple ones and failed in the middle
    """
    for allocation in reversed(allocation_result):
        logging.info("Rolling back allocation %s", str(allocation))
        ip_addresses = allocation.get("ipAddresses", None)
        for ip_address in ip_addresses:
            change_ip_status(swis, ip_address, "Available")


def get_free_ip(swis, range_id):
    """
    Reserve IP in network
    """
    componets = range_id.split(":")[1].split("/")
    address = componets[0]
    cidr = componets[1]
    ip_address = swis.invoke("IPAM.SubnetManagement", "StartIpReservation", \
                              address, cidr, 15)
    logging.info("Reserved IPNode %s ", ip_address)
    return ip_address


def change_ip_status(swis, ip_address, status):
    """
    Change IP status in IPAM
    IPAM support 4 node statuses:
       Used
       Available
       Reserve
       Transient
    """
    logging.info("Status IPNode %s changed to %s", ip_address, status)
    uri = "Invoke/IPAM.SubnetManagement/ChangeIpStatus"
    props = {
        'ipAddress': ip_address,
        'status': status
    }
    swis.update(uri, **props)


def get_subnet_id(range_id):
    """
    Get network SubnetID by RangeID
    """
    componets = range_id.split(":")[0].split("/")
    return componets[1]


def get_free_ips(swis, subnet_id):
    """
    Get list of free IPs in network by SubnetID
    """
    query = "SELECT DisplayName FROM IPAM.IPNode WHERE Status=2 AND "
    query += "DnsBackward IS NULL AND SubnetId='" + str(subnet_id) + "'"
    response = swis.query(query)
    free_ips = []
    if len(response["results"]) > 0:
        for free_ip in response["results"]:
            free_ips.append(free_ip["DisplayName"])
    return free_ips