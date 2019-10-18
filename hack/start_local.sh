#!/bin/bash

# A simple script for running the adapter locally against a local anchore engine for testing only

export SCANNER_ADAPTER_LISTEN_ADDR=":8081"
export SCANNER_ADAPTER_LOG_LEVEL="debug"
export ANCHORE_ENDPOINT="http://localhost:8228"
export ANCHORE_USERNAME="admin"
export ANCHORE_PASSWORD="foobar"
export ANCHORE_CLIENT_TIMEOUT_SECONDS=60
export ANCHORE_FILTER_VENDOR_IGNORED=false
export SCANNER_ADAPTER_FULL_VULN_DESCRIPTIONS=true

./bin/anchore-adapter
