#!/bin/bash

mkdir -p out/

python main.py -i test-data/openvex/vex_1.json -t OpenVEX -o out/openvex_cyclonedx_out.json --output-type CycloneDX --validate
python main.py -i test-data/openvex/vex_2.json -t OpenVEX -o out/openvex_cyclonedx_out_2.json --output-type CycloneDX --validate

python main.py -i test-data/openvex/vex_1.json -t OpenVEX -o out/openvex_csaf_out.json --output-type CSAF --validate
python main.py -i test-data/openvex/vex_2.json -t OpenVEX -o out/openvex_csaf_out_2.json --output-type CSAF --validate

python main.py -i test-data/cyclone_dx/vex_1.json -t CycloneDX -o out/cyclone_dx_openvex_out_1.json --output-type OpenVEX --validate
python main.py -i test-data/cyclone_dx/vex_2.json -t CycloneDX -o out/cyclone_dx_openvex_out_2.json --output-type OpenVEX --validate
