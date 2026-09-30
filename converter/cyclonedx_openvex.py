from typing import Any, Optional

from converter import BaseConverter


class CyclonedxOpenVexConverter(BaseConverter):

    @staticmethod
    def convert(input_data: dict[str, Any]) -> dict[str, Any]:
        output_data: dict[str, Any] = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "tooling": "PoC VEX Format Converter 1.0",
        }

        if "metadata" in input_data:
            if "authors" in input_data["metadata"]:
                author_list: str = ""
                for author in input_data["metadata"]["authors"]:
                    if "name" in author:
                        author_list += author["name"] + " "
                    if "email" in author:
                        author_list += "<" + author["email"] + "> "
                    if "phone" in author:
                        author_list += author["phone"] + " "
                    author_list = author_list[:-1] + "\n"
                output_data["author"] = author_list[:-1]

            if "timestamp" in input_data["metadata"]:
                output_data["timestamp"] = input_data["metadata"]["timestamp"]

            if "tools" in input_data["metadata"]:
                if "components" in input_data["metadata"]["tools"]:
                    for component in input_data["metadata"]["tools"]["components"]:
                        output_data["tooling"] += "\n" + component["name"]

                if "services" in input_data["metadata"]["tools"]:
                    for service in input_data["metadata"]["tools"]["services"]:
                        output_data["tooling"] += "\n" + service["name"]

        if "version" in input_data:
            output_data["version"] = input_data["version"]

        if "vulnerabilities" in input_data:
            for vulnerability in input_data["vulnerabilities"]:
                output_data["statements"] = output_data.get("statements", [])
                new_statement: dict[str, Any] = {}

                if "bom-ref" in vulnerability:
                    new_statement["@id"] = vulnerability["bom-ref"]

                if "analysis" in vulnerability:
                    if "firstIssued" in vulnerability["analysis"]:
                        new_statement["timestamp"] = vulnerability["analysis"][
                            "firstIssued"
                        ]

                    if "lastUpdated" in vulnerability["analysis"]:
                        new_statement["last_updated"] = vulnerability["analysis"][
                            "lastUpdated"
                        ]

                    if "state" in vulnerability["analysis"]:
                        status = (
                            "not_affected"
                            if vulnerability["analysis"]["state"] == "not_affected"
                            else (
                                "affected"
                                if vulnerability["analysis"]["state"] == "exploitable"
                                else (
                                    "fixed"
                                    if vulnerability["analysis"]["state"] == "resolved"
                                    else (
                                        "under_investigation"
                                        if vulnerability["analysis"]["state"]
                                        == "in_triage"
                                        else None
                                    )
                                )
                            )
                        )
                        if status is not None:
                            new_statement["status"] = status

                    if "detail" in vulnerability["analysis"]:
                        new_statement["status_notes"] = vulnerability["analysis"][
                            "detail"
                        ]

                    if "justification" in vulnerability["analysis"]:
                        justification = (
                            "component_not_present"
                            if vulnerability["analysis"]["justification"]
                            == "code_not_present"
                            else (
                                "vulnerable_code_not_in_execute_path"
                                if vulnerability["analysis"]["justification"]
                                == "code_not_reachable"
                                else (
                                    "inline_mitigations_already_exist"
                                    if vulnerability["analysis"]["justification"]
                                    == "protected_by_mitigating_control"
                                    else None
                                )
                            )
                        )
                        if justification is not None:
                            new_statement["justification"] = justification

                if "id" in vulnerability:
                    new_statement["vulnerability"] = new_statement.get(
                        "vulnerability", {}
                    )
                    new_statement["vulnerability"]["name"] = vulnerability["id"]
                    new_statement["vulnerability"]["@id"] = vulnerability["id"]

                if "description" in vulnerability:
                    new_statement["vulnerability"] = new_statement.get(
                        "vulnerability", {}
                    )
                    new_statement["vulnerability"]["description"] = vulnerability[
                        "description"
                    ]

                if "references" in vulnerability:
                    new_statement["vulnerability"] = new_statement.get(
                        "vulnerability", {}
                    )
                    new_statement["vulnerability"]["aliases"] = []
                    for reference in vulnerability["references"]:
                        new_statement["vulnerability"]["aliases"].append(
                            reference["id"]
                        )

                if "affects" in vulnerability:
                    for affected in vulnerability["affects"]:
                        new_statement["products"] = new_statement.get("products", [])
                        ref = affected["ref"]
                        found_component: Optional[dict[str, Any]] = None
                        if "metadata" in input_data:
                            if "component" in input_data["metadata"]:
                                if "bom-ref" in input_data["metadata"]["component"]:
                                    if (
                                        input_data["metadata"]["component"]["bom-ref"]
                                        == ref
                                    ):
                                        found_component = input_data["metadata"][
                                            "component"
                                        ]
                        if found_component is None:
                            if "components" in input_data:
                                for component in input_data["components"]:
                                    if "bom-ref" in component:
                                        if component["bom-ref"] == ref:
                                            found_component = component
                                            break
                        if found_component is not None:
                            new_product: dict[str, Any] = {}
                            new_product["@id"] = ref

                            if "purl" in found_component:
                                new_product["identifiers"] = new_product.get(
                                    "identifiers", {}
                                )
                                new_product["identifiers"]["purl"] = found_component[
                                    "purl"
                                ]

                            if "cpe" in found_component:
                                new_product["identifiers"] = new_product.get(
                                    "identifiers", {}
                                )
                                new_product["identifiers"][
                                    (
                                        "cpe22"
                                        if "cpe:2.2" in found_component["cpe"]
                                        else "cpe23"
                                    )
                                ] = found_component["cpe"]

                            if "hashes" in found_component:
                                for hash in found_component["hashes"]:
                                    new_product["hashes"] = new_product.get(
                                        "hashes", {}
                                    )
                                    new_product["hashes"][hash["alg"]] = hash["content"]

                            new_statement["products"].append(new_product)

                output_data["statements"].append(new_statement)

        return output_data
