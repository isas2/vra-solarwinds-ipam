#!/bin/bash

PROVIDER="SolarWinds"
MODULES=("AllocateIP" "DeallocateIP" "GetIPRanges" "ValidateEndpoint")

for MODULE in "${MODULES[@]}"
do
    MODULE_NAME="${PROVIDER}_${MODULE}"
    unzip -n src/lib_photon3.zip -d src/$MODULE_NAME
    cd src/$MODULE_NAME
    zip -rdu ../../bundle/$MODULE_NAME.zip *
    cd -
done

zip -rdu bundle.zip bundle
zip -du SolarWinds.zip bundle.zip registration.yaml endpoint-schema.json logo.png
