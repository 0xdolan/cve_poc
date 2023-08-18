#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: 0xdolan
Github: https://github.com/0xdolan/cve_poc.git
Description: PoC for CVE IDs
References: https://github.com/nomi-sec/PoC-in-GitHub, https://github.com/trickest/cve
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console

console = Console()


class CVEPoCFinder:
    def __init__(self):
        self.nomi_sec_poc_in_github = (
            "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
        )
        self.trickest_cve = "https://github.com/trickest/cve/blob/main"

    def validate_cve_id(self, cve_id):
        if "_" in cve_id:
            cve_id = cve_id.replace("_", "-")

        cve_year, cve_num = cve_id.split("-")[1:]

        current_year = datetime.today().year
        if int(cve_year) < 1999 or int(cve_year) > current_year:
            print(f"[-] Error: CVE ID must be between 1999-{current_year}")
            exit(1)

        return cve_id, cve_year, cve_num

    def fetch_results(self, cve_id):
        cve_id, cve_year, cve_num = self.validate_cve_id(cve_id)

        nomi_sec_poc_in_github_url = (
            f"{self.nomi_sec_poc_in_github}/{cve_year}/{cve_id}.json"
        )
        trickest_cve_url = f"{self.trickest_cve}/{cve_year}/{cve_id}.md"

        res_nomi_sec_poc_in_github_url = requests.get(nomi_sec_poc_in_github_url)
        res_trickest_cve_url = requests.get(trickest_cve_url)

        results = []
        if not any([res_nomi_sec_poc_in_github_url, res_trickest_cve_url]):
            print(f"[-] Error: {cve_id} not found!")
            exit(1)

        json_results = []
        if res_nomi_sec_poc_in_github_url.status_code == 200:
            json_response = res_nomi_sec_poc_in_github_url.json()
            for cve_item in json_response:
                url = cve_item["html_url"]
                description = cve_item["description"]
                json_results.append((url, description))
        results.extend(json_results)

        if res_trickest_cve_url.status_code == 200:
            results.append((trickest_cve_url, None))

        final_results = []
        for url, description in results:
            final_results.append(
                {
                    "url": url,
                    "description": description,
                }
            )
        return {f"{cve_id}": final_results}


def main():
    parser = argparse.ArgumentParser(description="CVE PoC Finder")
    parser.add_argument("-c", "--cve_id", required=True, help="CVE ID to search for")
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )

    args = parser.parse_args()

    poc_finder = CVEPoCFinder()
    results = poc_finder.fetch_results(args.cve_id)

    if args.json:
        output_results = json.dumps(results, indent=4, ensure_ascii=False, default=str)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(output_results)
        else:
            print(output_results)
    else:
        console.print(results)


if __name__ == "__main__":
    main()
