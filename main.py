import json
import argparse

def format_sarif(twistcli_version, results_file):
    with open(results_file, 'r') as file:
        scan = json.load(file)

    results = scan['results'][0]
    vuln_comps = results.get('vulnerabilities', []) + results.get('compliances', [])

    encountered_ids = set()  # new set to keep track of rule ids
    rules = []  # list to keep rules
    sarif_results = []  # list to keep results

    for vc in vuln_comps:
        if vc['id'] not in encountered_ids:
            encountered_ids.add(vc['id'])

            rule = {
                'id': f"{vc['id']}",
                'shortDescription': {
                    'text': f"[Prisma Cloud] {vc['id']} in {vc.get('packageName', '')}",
                },
                'fullDescription': {
                    'text': f"{vc['severity'].capitalize()} severity {vc['id']} found in {vc.get('packageName', '')} version {vc.get('packageVersion', '')}",
                },
                'help': {
                    'text': '',
                    'markdown': f"| {vc['id']} | {vc['severity']} | {vc.get('cvss', 'N/A')} | {vc.get('packageName', '')} | {vc.get('packageVersion', '')} | {vc.get('status', 'not fixed')} | {vc.get('publishedDate', '')} | {vc.get('discoveredDate', '')} |",
                },
                'properties': {
                    'security-severity': f"{vc.get('cvss', '0.0')}",
                },
            }

            result = {
                'ruleId': f"{vc['id']}",
                'level': 'warning',
                'message': {
                    'text': f"Description:\n{vc.get('description', '')}",
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': results['name'],
                        },
                        'region': {
                            'startLine': 1,
                            'startColumn': 1,
                            'endLine': 1,
                            'endColumn': 1,
                        },
                    },
                }]
            }

            rules.append(rule)
            sarif_results.append(result)

    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Prisma Cloud (twistcli)',
                    'version': twistcli_version,
                    'rules': rules,
                },
            },
            'results': sarif_results,
        }],
    }


def main():
    parser = argparse.ArgumentParser(description="Format SARIF.")
    parser.add_argument('-t', '--twistcli', required=True, help='Twistcli version')
    parser.add_argument('-r', '--results', required=True, help='Path to the results JSON file')
    parser.add_argument('-o', '--output', default='output.json', help='Path to the output JSON file (default: output.json)')

    args = parser.parse_args()

    result = format_sarif(twistcli_version=args.twistcli, results_file=args.results)

    with open(args.output, 'w') as outfile:
        json.dump(result, outfile, indent=2)

    print(f"Output written to {args.output}")

if __name__ == "__main__":
    main()
