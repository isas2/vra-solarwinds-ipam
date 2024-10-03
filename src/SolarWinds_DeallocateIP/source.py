"""
Copyright (c) 2020 Aleksandr Istomin, https://as.zabedu.ru

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
    Create IPAM object,
    define deaalocate_ip function
    and start deallocation function
    """
    ipam = IPAM(context, inputs)
    IPAM.do_deallocate_ip = do_deallocate_ip
    return ipam.deallocate_ip()


def do_deallocate_ip(self, auth_credentials, _):
    """
    Main function.
    Get inputs,
    create connection with IPAM server,
    execute operation and
    prepare results
    """
    username = auth_credentials["privateKeyId"]
    password = auth_credentials["privateKey"]
    ignore_ssl_warning = self.inputs["endpoint"]["endpointProperties"] \
                                  ["ignoreSslWarning"].lower() == "true"
    if ignore_ssl_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    swis = SwisClient(self.inputs["endpoint"]["endpointProperties"]
                                 ["hostName"], username, password, self.inputs["endpoint"]["endpointProperties"]["apiPort"])

    deallocation_result = []
    for deallocation in self.inputs["ipDeallocations"]:
        deallocation_result.append(deallocate(swis, deallocation))

    assert len(deallocation_result) > 0
    return {
        "ipDeallocations": deallocation_result
    }


def deallocate(swis, deallocation):
    """
    Set IPNode status to Available
    """
    ip_range_id = deallocation["ipRangeId"]
    ip_address = deallocation["ipAddress"]
    logging.info("Deallocating IP %s from range %s", ip_address, ip_range_id)
    change_ip_status(swis, ip_address, "Available")

    return {
        "ipDeallocationId": deallocation["id"],
        "message": "Success"
    }


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
