from typing import Any

from converter import BaseConverter


class OpenVexCyclonedxConverter(BaseConverter):

    @staticmethod
    def convert_component(
        component: dict[str, Any], publisher: None | str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        version = "Unknown"
        if "@" in component["@id"]:
            version = component["@id"].split("@")[1]
        component_data = {
            "bom-ref": component["@id"],
            "type": "application",  # FIXME: have option to override type
            "name": component["@id"],
            "version": version,
        }

        if "identifiers" in component:
            if "purl" in component["identifiers"]:
                component_data["purl"] = component["identifiers"]["purl"]
            if "cpe23" in component["identifiers"]:
                component_data["cpe"] = component["identifiers"]["cpe23"]
            elif "cpe22" in component["identifiers"]:
                component_data["cpe"] = component["identifiers"]["cpe22"]

        if "hashes" in component:
            component_data["hashes"] = []
            for alg, value in component["hashes"].items():
                component_data["hashes"].append({"alg": alg, "content": value})

        dependencies: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = [component_data]
        if "subcomponents" in component:
            for subcomponent in component["subcomponents"]:
                new_components, new_dependencies = (
                    OpenVexCyclonedxConverter.convert_component(subcomponent, publisher)
                )
                components.extend(new_components)
                dependencies.extend(new_dependencies)
                dependencies.append(
                    {"ref": subcomponent["@id"], "dependsOn": [component["@id"]]}
                )

        return components, dependencies

    @staticmethod
    def convert(input_data: dict[str, Any]) -> dict[str, Any]:
        output_data: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "PoC VEX Format Converter",
                            "version": "1.0",
                            "authors": [{"name": "Maximilian Waidelich"}],
                        }
                    ]
                }
            },
        }

        if "author" in input_data:
            output_data["metadata"] = output_data.get("metadata", {})
            output_data["metadata"]["authors"] = output_data["metadata"].get(
                "authors", []
            )
            output_data["metadata"]["authors"].append({"name": input_data["author"]})
            if "role" in input_data:
                output_data["metadata"]["authors"][-1] += f" {input_data['role']}"

        if "timestamp" in input_data:
            output_data["metadata"] = output_data.get("metadata", {})
            output_data["metadata"]["timestamp"] = input_data["timestamp"]

        if "version" in input_data:
            output_data["version"] = input_data["version"]

        if "tooling" in input_data:
            output_data["metadata"] = output_data.get("metadata", {})
            output_data["metadata"]["tools"] = output_data["metadata"].get("tools", {})
            output_data["metadata"]["tools"]["components"] = output_data["metadata"][
                "tools"
            ].get("components", [])
            # FIXME: have option to override type
            output_data["metadata"]["tools"]["components"].append(
                {"type": "application", "name": input_data["tooling"]}
            )

        if "statements" in input_data:
            for statement in input_data["statements"]:
                output_data["vulnerabilities"] = output_data.get("vulnerabilities", [])
                new_vulnerability: dict[str, Any] = {}

                if "@id" in statement:
                    new_vulnerability["bom-ref"] = statement["@id"]

                if "vulnerability" in statement:
                    if "@id" in statement["vulnerability"]:
                        new_vulnerability["source"] = {
                            "name": statement["vulnerability"]["@id"]
                        }
                    if "name" in statement["vulnerability"]:
                        new_vulnerability["id"] = statement["vulnerability"]["name"]
                    if "description" in statement["vulnerability"]:
                        new_vulnerability["description"] = statement["vulnerability"][
                            "description"
                        ]
                    if "aliases" in statement["vulnerability"]:
                        new_vulnerability["references"] = []
                        for alias in statement["vulnerability"]["aliases"]:
                            new_vulnerability["references"].append(
                                {"id": alias, "source": {}}
                            )

                if "timestamp" in statement:
                    new_vulnerability["analysis"] = {}
                    new_vulnerability["analysis"]["firstIssued"] = statement[
                        "timestamp"
                    ]

                if "last_updated" in statement:
                    new_vulnerability["analysis"] = new_vulnerability.get(
                        "analysis", {}
                    )
                    new_vulnerability["analysis"]["lastUpdated"] = statement[
                        "last_updated"
                    ]

                output_data["components"] = output_data.get("components", [])
                output_data["dependencies"] = output_data.get("dependencies", [])
                new_vulnerability["affects"] = []
                for product in statement["products"]:
                    new_vulnerability["affects"].append({"ref": product["@id"]})
                    if [
                        x
                        for x in output_data["components"]
                        if x["bom-ref"] == product["@id"]
                    ]:
                        continue
                    new_components, new_dependencies = (
                        OpenVexCyclonedxConverter.convert_component(
                            product, statement.get("supplier", None)
                        )
                    )

                    output_data["components"].extend(new_components)
                    output_data["dependencies"].extend(new_dependencies)

                if "status" in statement:
                    new_vulnerability["analysis"] = new_vulnerability.get(
                        "analysis", {}
                    )
                    new_vulnerability["analysis"]["state"] = (
                        "not_affected"
                        if statement["status"] == "not_affected"
                        else (
                            "exploitable"
                            if statement["status"] == "affected"
                            else (
                                "resolved"
                                if statement["status"] == "fixed"
                                else ("in_triage")
                            )
                        )
                    )  # if "under_investigation"

                if "status_notes" in statement:
                    new_vulnerability["analysis"] = new_vulnerability.get(
                        "analysis", {}
                    )
                    new_vulnerability["analysis"]["detail"] = statement["status_notes"]

                if "justification" in statement:
                    justification = (
                        "code_not_present"
                        if statement["justification"]
                        in ["component_not_present", "vulnerable_code_not_present"]
                        else (
                            "code_not_reachable"
                            if statement["justification"]
                            == "vulnerable_code_not_in_execute_path"
                            else (
                                "protected_by_mitigating_control"
                                if statement["justification"]
                                == "inline_mitigations_already_exist"
                                else None
                            )
                        )
                    )
                    if justification is not None:
                        new_vulnerability["analysis"] = new_vulnerability.get(
                            "analysis", {}
                        )
                        new_vulnerability["analysis"]["justification"] = justification

                if "impact_statement" in statement:
                    new_vulnerability["analysis"] = new_vulnerability.get(
                        "analysis", {}
                    )
                    new_vulnerability["analysis"]["detail"] = (
                        new_vulnerability.get("detail", "")
                        + "Impact Statement:\n"
                        + statement["impact_statement"]
                    )

                if "action_statement" in statement:
                    new_vulnerability["analysis"] = new_vulnerability.get(
                        "analysis", {}
                    )
                    new_vulnerability["analysis"]["detail"] = (
                        new_vulnerability.get("detail", "")
                        + "Action Statement:\n"
                        + statement["action_statement"]
                    )

                output_data["vulnerabilities"].append(new_vulnerability)

        return output_data
