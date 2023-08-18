# CVE Proof of Concept

find Proof of concept (PoC) repos for CVEs

<pre align="center"><code>

   ______ _    __    ______           ____           ______
  / ____/| |  / /   / ____/          / __ \  ____   / ____/
 / /     | | / /   / __/            / /_/ / / __ \ / /     
/ /___   | |/ /   / /___           / ____/ / /_/ // /___   
\____/   |___/   /_____/          /_/      \____/ \____/   
                                                           
</pre></code>

<p align="center">
  <a href="#how-it-works">How</a> •
  <a href="#install">Install</a>
</p>
<br><br>

## How it works

[![screenshot_001](./img/001.jpg)](./img/001.jpg)

## Install

1. Install the requirements:

   ```bash
   pip install -r requirements.txt

   # or use pip3

   pip3 install -r requirements.txt

   # or

   python3 -m pip install -r requirements.txt
   ```

2. Open the terminal and run the cve_poc.py file as follows:

To get all CVEs for 2023:

```bash
python cve_poc.py -y 2023

```

To search for an exact one:

```bash
python cve_poc.py -c "CVE-2023-1671"

```

To save the output as JSON:

```bash
python cve_poc.py -c "CVE-2023-1671" -o cve.json
```

## License

Licensed under the GPLv3 License.
