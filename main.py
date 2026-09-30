import argparse
import json
import os.path
import subprocess
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

import converter


def main():
    types = ["CycloneDX", "CSAF", "OpenVEX"]
    args = argparse.ArgumentParser()
    args.add_argument("-i", "--input", dest="input_file", required=True)
    args.add_argument("-t", "--type", choices=types, dest="input_type", required=True)
    args.add_argument("-o", "--output", dest="output_file", required=True)
    args.add_argument("--output-type", choices=types, dest="output_type", required=True)
    args.add_argument("--validate", dest="validate", action="store_true")
    arguments = args.parse_args()

    input_file = arguments.input_file
    input_type = arguments.input_type
    output_file = arguments.output_file
    output_type = arguments.output_type
    validate = arguments.validate

    if not os.path.isfile(input_file):
        args.error("Input file does not exist")

    with open(input_file, "r") as f:
        input_data = json.load(f)

    if input_type == output_type:
        print("Conversion to same type isn't possible, nothing to do")
        sys.exit(1)

    active_converter: type[converter.BaseConverter]
    if input_type == "OpenVEX" and output_type == "CycloneDX":
        active_converter = converter.OpenVexCyclonedxConverter
    elif input_type == "OpenVEX" and output_type == "CSAF":
        active_converter = converter.OpenVexCsafConverter
    elif input_type == "CycloneDX" and output_type == "OpenVEX":
        active_converter = converter.CyclonedxOpenVexConverter
    else:
        print(f"Unsupported conversion from {input_type} to {output_type}")
        sys.exit(1)

    out_data = json.dumps(active_converter.convert(input_data), indent=2)
    with open(output_file, "w") as f:
        f.write(out_data)
    if validate:
        if output_type == "CycloneDX":
            validation = JsonValidator(SchemaVersion.V1_7).validate_str(out_data)
            if validation is not None:
                print(validation.data)
                sys.exit(1)
        if output_type == "OpenVEX":
            subprocess.run(
                ["docker", "build", "-q", "-t", "openvex-validator", "."], check=True
            )
            try:
                subprocess.run(
                    [
                        "docker",
                        "run",
                        "-v",
                        f"./{os.path.relpath(output_file)}:/tmp/openvex.json:ro",
                        "openvex-validator",
                        "/tmp/openvex.json",
                    ],
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                print(
                    f"Error running openvex-validator for file {output_file}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    main()
