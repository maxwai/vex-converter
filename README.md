# VEX Format converter

## Environment

The script needs python.

Python 3.14 was used during development but other versions may also work.

## Prerequirements

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

If OpenVEX documents should be validated, a working docker installation is needed.

## Run

Execute `python main .py -h` to see the parameter flags.

Example execution:

```bash
python main.py -i test-data/openvex/vex_1.json -t OpenVEX -o out/openvex_cyclonedx_out.json --output-type CycloneDX --validate
```

## Possible conversions

Currently following conversions are possible:

- OpenVEX $\rightarrow$ CycloneDX
- OpenVEX $\rightarrow$ CSAF
- CycloneDx $\rightarrow$ OpenVEX

## Output validation

Each output format has a different way of being validated.

CycloneDX is validated with the `cyclonedx-python-lib` package, needing no further interaction.

OpenVEX is validated using a Docker image that is build if needed.
This Docker image uses the `vexctl` CLI tool provided by OpenVEX.

CSAF can't be validated automatically, instead the generated JSON needs to be inserted into [Secvisogram](https://secvisogram.github.io/).

## Test all available conversions

A convenience script is provided to run all possible conversions from the test data files: `test_conversions.sh`.

## Limitations

Here limitation other than missing mappings are documented.

### OpenVEX to CycloneDX

Components and Tools always have the type `application`.

### OpenVEX to CSAF

`role` is mapped 1:1 to `document/publisher/category`, need to manually change to value from enum.

Only provided information is put into csaf document, additional information needs to be inserted so that it is valid, such as document name, publisher namespace & category, vulnerability note. 

Duplicate vulnerabilites (for example with different states), will be ignored, only the first entry is converted.

### CycloneDX to OpenVEX

No check is made if the inserted `@id` fields are IRIs.

Information that is missing in the source file but required in the destination file like author or document id isn't inserted.
