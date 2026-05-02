#!/bin/bash
source ~/SOC-ELK/.env
export ELASTIC_PASSWORD
sed "s/\${ELASTIC_PASSWORD}/$ELASTIC_PASSWORD/" ~/SOC-ELK/elastalert/config.yml > /tmp/elastalert-config.yml
elastalert --config /tmp/elastalert-config.yml --verbose
