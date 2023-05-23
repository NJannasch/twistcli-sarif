# Prisma Cloud Twistcli to SARIF Converter

This Python script is designed to convert the output of Prisma Cloud's `twistcli` utility to the Static Analysis Results Interchange Format (SARIF).

## Description

The `twistcli` utility is a command-line tool provided by Prisma Cloud that scans container images and generates a report detailing any vulnerabilities found. This script takes the JSON output from `twistcli` and converts it into SARIF format. SARIF is a standard format for the output of static analysis tools, making it easier to integrate `twistcli` with other tools or processes that support SARIF.

## Requirements

- Python 3.x

## Usage

1. Run your `twistcli` scan and output the results to a JSON file.
2. Run this script with the `twistcli` version and the path to your JSON file as arguments.

Example:

```bash
python main.py --twistcli "123" --results "results.json" --output "output.json"
```

## Arguments:

- **-t**/**--twistcli**: The version of twistcli you used to generate your scan results.
- **-r**/**--results**: The path to the JSON file containing your scan results.
- **-o**/**--output**: The path to the output JSON file. If you don't specify an output file, it defaults to output.json.

## Output
The script outputs a SARIF-compliant JSON file, detailing the results of the scan including any vulnerabilities and compliance checks.

## License
This project is licensed under the terms of the MIT license.
