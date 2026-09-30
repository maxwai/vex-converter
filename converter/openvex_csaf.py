from datetime import datetime, timezone
from typing import Any

from converter import BaseConverter


class OpenVexCsafConverter(BaseConverter):

    @staticmethod
    def convert_product(component: dict[str, Any]) -> list[dict[str, Any]]:
        product_data = {"product_id": component["@id"], "name": component["@id"]}

        if "identifiers" in component:
            product_data["product_identification_helper"] = {}
            if "purl" in component["identifiers"]:
                product_data["product_identification_helper"]["purl"] = component[
                    "identifiers"
                ]["purl"]
            if "cpe23" in component["identifiers"]:
                product_data["product_identification_helper"]["cpe"] = component[
                    "identifiers"
                ]["cpe23"]
            elif "cpe22" in component["identifiers"]:
                product_data["product_identification_helper"]["cpe"] = component[
                    "identifiers"
                ]["cpe22"]

        if "hashes" in component:
            product_data["product_identification_helper"] = product_data.get(
                "product_identification_helper", {}
            )
            product_data["product_identification_helper"]["hashes"] = product_data[
                "product_identification_helper"
            ].get("hashes", {})
            for alg, value in component["hashes"].items():
                product_data["product_identification_helper"]["hashes"].append(
                    {"file_hashes": {"algorithm": alg, "value": value}}
                )

        components: list[dict[str, Any]] = [product_data]
        if "subcomponents" in component:
            for subcomponent in component["subcomponents"]:
                new_components = OpenVexCsafConverter.convert_product(subcomponent)
                components.extend(new_components)

        return components

    @staticmethod
    def convert(input_data: dict[str, Any]) -> dict[str, Any]:
        output_data: dict[str, Any] = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "tracking": {
                    "generator": {
                        "date": datetime.now(timezone.utc).isoformat(),
                        "engine": {
                            "name": "PoC VEX Format Converter",
                            "version": "1.0",
                        },
                    }
                },
            },
        }

        if "@id" in input_data:
            output_data["document"]["tracking"]["id"] = input_data["@id"]

        if "author" in input_data:
            output_data["document"]["publisher"] = output_data["document"].get(
                "publisher", {}
            )
            output_data["document"]["publisher"]["name"] = input_data["author"]
            if "role" in input_data:
                output_data["document"]["publisher"][
                    "category"
                ] += f" {input_data['role']}"

        if "timestamp" in input_data:
            output_data["document"]["tracking"]["current_release_date"] = input_data[
                "timestamp"
            ]

        if "last_updated" in input_data:
            output_data["document"]["tracking"]["revision_history"] = output_data[
                "document"
            ]["tracking"].get("revision_history", [])
            output_data["document"]["tracking"]["revision_history"].append(
                {
                    "date": input_data["last_updated"],
                }
            )

        if "version" in input_data:
            output_data["document"]["tracking"]["version"] = str(input_data["version"])

        if "tooling" in input_data:
            output_data["document"]["tracking"]["generator"]["engine"]["name"] = (
                input_data["tooling"]
            )
            del output_data["document"]["tracking"]["generator"]["engine"]["version"]
            del output_data["document"]["tracking"]["generator"]["date"]

        if "statements" in input_data:
            for statement in input_data["statements"]:
                output_data["vulnerabilities"] = output_data.get("vulnerabilities", [])
                new_vulnerability: dict[str, Any] = {}

                if "@id" in statement:
                    new_vulnerability["ids"] = new_vulnerability.get("ids", [])
                    new_vulnerability["ids"].append({"text": statement["@id"]})

                if "vulnerability" in statement:
                    if "@id" in statement["vulnerability"]:
                        new_vulnerability["references"] = new_vulnerability.get(
                            "references", []
                        )
                        new_vulnerability["references"].append(
                            {"url": statement["vulnerability"]["@id"]}
                        )
                    if "name" in statement["vulnerability"]:
                        if statement["vulnerability"]["name"].startswith("CVE-"):
                            if [
                                x
                                for x in output_data["vulnerabilities"]
                                if x["cve"] == statement["vulnerability"]["name"]
                            ]:
                                print(
                                    f"Got {statement["vulnerability"]["name"]} twice, skipping additional instance"
                                )
                                continue
                            new_vulnerability["cve"] = statement["vulnerability"][
                                "name"
                            ]
                        else:
                            new_vulnerability["references"] = new_vulnerability.get(
                                "references", []
                            )
                            new_vulnerability["references"].append(
                                {"url": statement["vulnerability"]["name"]}
                            )
                    if "description" in statement["vulnerability"]:
                        new_vulnerability["notes"] = new_vulnerability.get("notes", [])
                        new_vulnerability["notes"].append(
                            {"text": statement["vulnerability"]["description"]}
                        )
                    if "aliases" in statement["vulnerability"]:
                        for alias in statement["vulnerability"]["aliases"]:
                            new_vulnerability["references"] = new_vulnerability.get(
                                "references", []
                            )
                            new_vulnerability["references"].append({"url": alias})

                if "timestamp" in statement:
                    new_vulnerability["release_date"] = statement["timestamp"]

                output_data["product_tree"] = output_data.get("product_tree", {})
                output_data["product_tree"]["full_product_names"] = output_data[
                    "product_tree"
                ].get("full_product_names", [])
                product_ids: list[str] = []
                for product in statement["products"]:
                    new_components = OpenVexCsafConverter.convert_product(product)
                    product_ids.extend([x["product_id"] for x in new_components])
                    output_data["product_tree"]["full_product_names"].extend(
                        [
                            x
                            for x in new_components
                            if x["product_id"]
                            not in [
                                x["product_id"]
                                for x in output_data["product_tree"][
                                    "full_product_names"
                                ]
                            ]
                        ]
                    )

                if "status" in statement:
                    new_vulnerability["product_status"] = new_vulnerability.get(
                        "product_status", {}
                    )
                    status_key = (
                        "not_affected"
                        if statement["status"] == "not_affected"
                        else (
                            "known_affected"
                            if statement["status"] == "affected"
                            else (
                                "fixed"
                                if statement["status"] == "fixed"
                                else ("under_investigation")
                            )
                        )
                    )  # if "under_investigation"
                    new_vulnerability["product_status"][status_key] = new_vulnerability[
                        "product_status"
                    ].get(status_key, [])
                    new_vulnerability["product_status"][status_key].extend(product_ids)

                if "status_notes" in statement:
                    new_vulnerability["notes"] = new_vulnerability.get("notes", [])
                    new_vulnerability["notes"].append(
                        {"text": statement["status_notes"]}
                    )

                if "justification" in statement:
                    new_vulnerability["flags"] = statement["justification"]

                if "impact_statement" in statement:
                    new_vulnerability["threats"] = new_vulnerability.get("threats", [])
                    new_vulnerability["threats"].append(
                        {"category": "impact", "details": statement["impact_statement"]}
                    )

                if "action_statement" in statement:
                    new_vulnerability["remediations"] = new_vulnerability.get(
                        "remediations", []
                    )
                    new_vulnerability["remediations"].append(
                        {"details": statement["action_statement"]}
                    )

                    new_vulnerability["remediations"][-1]["product_ids"] = product_ids

                    if "action_statement_timestamp" in statement:
                        new_vulnerability["remediations"][-1]["date"] = statement[
                            "action_statement_timestamp"
                        ]

                output_data["vulnerabilities"].append(new_vulnerability)

        return output_data
