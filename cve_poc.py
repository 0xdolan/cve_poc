#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: 0xdolan
Github: github.com/0xdolan
Description: PoC for CVE ID using PoC-in-GitHub repo
Usage: python PoC_in_GitHub.py -c CVE-2023-XXXXX
References: https://github.com/nomi-sec/PoC-in-GitHub
Date: August 2023
"""

import argparse
import io
import json
import os
import re
import sys
from pathlib import Path

import pyfiglet
import requests
from rich.console import Console

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")

console = Console()


class PoCInGitHub:
    def __init__(self):
        self.current_path = Path(__file__).parent.absolute()
        self.repo_link = "https://github.com/nomi-sec/PoC-in-GitHub"
        self.repo_path = self.current_path / "PoC-in-GitHub"

    def clone_repo(self, url):
        repo_name = url.split("/")[-1].split(".")[0]
        repo_path = self.current_path / repo_name

        if repo_path.exists():
            console.print("\n[+] Repo already exists\n")
            return repo_path

        if requests.get(url).status_code != 200:
            console.print("\n[-] Invalid URL\n")
            sys.exit(1)

        console.print("\n[+] Cloning repo\n")
        os.system(f"git clone {url} {repo_path}")

    def search_json_files(self, path):
        json_files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".json"):
                    json_files.append(os.path.join(root, file))
        return json_files

    def read_json(self, json_file):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def search_cve(self, json_files, cve):
        cve_list = []
        for file in json_files:
            data = self.read_json(file)
            for i in data:
                if cve in i.values():
                    cve_list.append(i)

        if len(cve_list) == 0:
            cve = cve.lower()
            for file in json_files:
                data = self.read_json(file)
                for i in data:
                    if cve in i.values() or re.match(rf"^{cve}.*", i["name"]):
                        cve_list.append(i)

        cve_list = [dict(t) for t in {str(d): d for d in cve_list}.values()]

        return cve_list

    def get_cve_details(self, cve, sort_by_forks=False):
        cves = self.search_cve(self.search_json_files(self.repo_path), cve)

        res = []
        for i in cves:
            result = dict()
            result["name"] = i["name"].upper()
            result["github_repo"] = i["html_url"]
            result["description"] = i["description"]
            result["forks"] = i["forks"]
            res.append(result)

        if sort_by_forks:
            res = sorted(res, key=lambda x: list(x.values())[0]["forks"], reverse=True)

        return res

    def update_repo(self):
        if not self.repo_path.exists():
            console.print("\n[-] Repo does not exist\n")
            sys.exit(1)

        console.print("\n[+] Updating repo\n")
        os.system(f"git -C {self.repo_path} pull")

        console.print(f"\n[+] Repo updated: {self.repo_path}\n")
        return

    def parse_args(self):
        parser = argparse.ArgumentParser(description="PoC for CVE IDs")
        parser.add_argument(
            "-c", "--cve", type=str, help="CVE ID (e.g. CVE-2021-41773)", required=False
        )
        parser.add_argument(
            "-up",
            "--update",
            action="store_true",
            help="Update PoC-in-GitHub repo",
            required=False,
        )
        parser.add_argument(
            "-o",
            "--output",
            type=str,
            help="Output file (e.g. output.json)",
            required=False,
        )
        args = parser.parse_args()
        return args

    def main(self):
        args = self.parse_args()
        cve = args.cve
        update = args.update
        output = args.output

        if not cve and not update:
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
            console.print("\n[-] Please provide CVE ID")
            console.print(f'[+] Usage: python {sys.argv[0]} -c "CVE-2023-XXXXX"\n')
            sys.exit(1)

        if not self.repo_path.exists():
            console.print("\n[-] Repo does not exist")
            console.print(f"[+] Do you want to clone the repo? (y/n)\n")
            choice = input()
            if choice.lower() == "y" or choice.lower() == "yes":
                self.clone_repo(self.repo_link)

        if update:
            self.update_repo()
            sys.exit(1)

        results = self.get_cve_details(cve)

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            console.print(f"\n[+] Output file: {output}\n")
        else:
            if len(results) == 0:
                console.print("\n[-] No results found\n")
                sys.exit(1)
            print()
            print(json.dumps(results, indent=4, ensure_ascii=False, default=str))
            print()


if __name__ == "__main__":
    poc_in_github = PoCInGitHub()
    poc_in_github.main()
