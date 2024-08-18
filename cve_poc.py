#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: 0xdolan
Github: https://github.com/0xdolan/cve_poc.git
Description: find Proof of concept (PoC) repos for CVEs
"""

import argparse
import json
import sys
from datetime import datetime

import pyfiglet
import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()


class CVEPoCFinder:
    def __init__(self):
        self.nomi_sec_poc_in_github = (
            "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
        )
        self.trickest_cve = "https://github.com/trickest/cve/blob/main"

    def validate_cve_id(self, cve_id):
        cve_id = cve_id.replace("_", "-").strip()
        cve_year, cve_num = cve_id.split("-")[1:]

        current_year = datetime.today().year
        if not (1999 <= int(cve_year) <= current_year):
            console.print(f"[-] Error: CVE ID must be between 1999-{current_year}")
            exit(1)

        return cve_id, cve_year, cve_num

    def fetch_results(self, cve_id):
        cve_id, cve_year, cve_num = self.validate_cve_id(cve_id)
        nomi_sec_url = f"{self.nomi_sec_poc_in_github}/{cve_year}/{cve_id}.json"
        trickest_url = f"{self.trickest_cve}/{cve_year}/{cve_id}.md"

        res_nomi_sec = requests.get(nomi_sec_url)
        res_trickest = requests.get(trickest_url)

        results = []

        if res_trickest.status_code == 200:
            soup = BeautifulSoup(res_trickest.text, "lxml")
            selector = "#repo-content-pjax-container > react-app > div > div > div.Box-sc-g0xbh4-0.fSWWem > div > div > div.Box-sc-g0xbh4-0.emFMJu > div.Box-sc-g0xbh4-0.hlUAHL > div > div:nth-child(3) > div.Box-sc-g0xbh4-0.iJmJly > div > div.Box-sc-g0xbh4-0.ytOJl > section > div > article > p:nth-child(4)"
            des = soup.select_one(selector)
            if des:
                results.append({"url": trickest_url, "description": des.text})
            else:
                results.append({"url": trickest_url, "description": None})

        if res_nomi_sec.status_code == 200:
            json_response = res_nomi_sec.json()
            for cve_item in json_response:
                url = cve_item["html_url"]
                description = cve_item["description"]
                results.append({"url": url, "description": description})

        return {cve_id: results}

    def get_cve_by_year(self, year):
        urls = [
            f"https://github.com/trickest/cve/tree/main/{year}",
            f"https://github.com/nomi-sec/PoC-in-GitHub/tree/master/{year}",
        ]

        results = []

        for url in urls:
            res = requests.get(url)
            soup = BeautifulSoup(res.text, "lxml")
            script_tag = soup.find(
                "script",
                {
                    "type": "application/json",
                    "data-target": "react-app.embeddedData",
                },
            )
            if script_tag:
                json_data = script_tag.string.strip()
                data = json.loads(json_data)
                items = data["payload"]["tree"]["items"]

                total = len(items)
                cve_titles = [item["name"].split(".")[0] for item in items]

            results.append({"url": url, "total": total, "cve_titles": cve_titles})

        return results


def main():
    parser = argparse.ArgumentParser(description="CVE PoC Finder")
    parser.add_argument("-c", "--cve_id", help="CVE ID to search for")
    parser.add_argument("-y", "--year", type=int, help="CVE year to search for")
    parser.add_argument("-o", "--output", help="Output file for JSON results")
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    args = parser.parse_args()

    if not any([bool(x) for x in vars(args).values()]):
        print()
        console.print(
            pyfiglet.figlet_format(
                "CVE PoC",
                font="slant",
                justify="center",
            )
        )
        console.print(
            pyfiglet.figlet_format(
                "by: 0xdolan",
                font="term",
                justify="center",
            )
        )
        print()
        console.print("\n[-] Please provide either --cve_id or --year option.")
        sys.exit(1)

    if args.year:
        poc_finder = CVEPoCFinder()
        cve_results = poc_finder.get_cve_by_year(args.year)
    elif args.cve_id:
        poc_finder = CVEPoCFinder()
        cve_results = poc_finder.fetch_results(args.cve_id)
    else:
        console.print("Please provide either --cve_id or --year option. Run -")
        return

    output_results = json.dumps(cve_results, indent=4, ensure_ascii=False, default=str)

    if args.json:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(output_results)
        else:
            console.print(output_results)
    else:
        console.print(cve_results)


if __name__ == "__main__":
    main()
