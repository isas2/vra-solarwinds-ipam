SolarWinds IPAM Integration Plugin
===================

A implementation of an SolarWinds IPAM integration plugin for vRA 8.x

This plugin is developed using IPAM SDK: [VMware vRealize Automation Third-Party IPAM SDK]

[VMware vRealize Automation Third-Party IPAM SDK]: https://code.vmware.com/web/sdk/1.1.0/vmware-vrealize-automation-third-party-ipam-sdk

For customization and installation details of this plugin see: [vRA 8: plugin SolarWinds IPAM]

[vRA 8: plugin SolarWinds IPAM]: https://as.zabedu.ru/virtual/vmware/vrealize/vra-solarwinds-ipam

For more information about the IPAM integration see: [vRA IPAM plugin reference documentation]

[vRA IPAM plugin reference documentation]: https://docs.vmware.com/en/vRealize-Automation/8.2/ipam_integration_contract_reqs.pdf

Scripts and package
===================

Under ./src/ you'd find separate directory for each IPAM specific operation that the plugin supports.

| Operation name              | Description                                                                                                                               | Script                                          | Required |
| ----------------------------|:------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------|:---------|
| Allocate IP                 | Allocates the next available IP for a VM                                                                                                  | ./src/main/python/allocate_ip/source.py         | Yes      |
| Deallocate IP               | Deallocates an already allocated IP                                                                                                       | ./src/main/python/deallocate_ip/source.py       | Yes      |
| Get IP Ranges               | Data collects IP networks from the IPAM provider                                                                                          | ./src/main/python/get_ip_ranges/source.py       | Yes      |
| Validate Endpoint           | Validates that the IPAM endpoint credentials are valid and that a connection to the external IPAM system can be established successfully  | ./src/main/python/validate_endpoint/source.py   | Yes      |

The ./src/\*\*/source.py scripts contain the Python source code that would be used by vRA to perform the respective IPAM operation.

The `_create_package.sh` script is used to package Python scripts and dependencies into the SolarWinds.zip plugin archive.

The `./src/lib_photon3.zip` contains all 3rd party libraries that the SolarWinds IPAM plugin depends on, they are unpacked during the execution of the `_create_package.sh` script. This will ensure that all Python libraries and binaries are Photon OS compliant.

The `SolarWinds.zip` contains a plugin ready for installation in vRA 8.x.
