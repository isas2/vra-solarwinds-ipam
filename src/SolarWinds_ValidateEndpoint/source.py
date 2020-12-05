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
    Create IPAM object and start allocation function
    """
#    try:
    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint
    return ipam.validate_endpoint()
#    except Exception as error:
#        logging.error("Unexpected exception: %s", str(error))
#        return ipam._build_error_response("5000", str(error))


def do_validate_endpoint(self, auth_credentials, _):
    """
    Main function.
    Get inputs,
    create connection with IPAM server,
    execute test request and
    prepare results
    """
    try:
        username = auth_credentials["privateKeyId"]
        password = auth_credentials["privateKey"]
        ignore_ssl_warning = self.inputs["endpointProperties"] \
                                      ["ignoreSslWarning"].lower() == "true"
        if ignore_ssl_warning:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        swis = SwisClient(self.inputs["endpointProperties"]["hostName"], \
                          username, password)

        logging.info("Start testing endpoint")
        query = """SELECT TOP 3 NodeID, DisplayName
                   FROM Orion.Nodes
                   WHERE DisplayName='test_request'
                """
        response = swis.query(query)
        logging.info("Received the following response: %s", str(response))
        if response:
            return {
                "message": "Validated successfully",
                "statusCode": "200"
            }

    except Exception as error:
        logging.error("Unexpected exception: %s", str(error))
        raise error
        #return self._build_error_response("5000", str(error))
    return None
