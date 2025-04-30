import json
import sys
from texttable import Texttable

def generate_report(data, out_file):
    domain_section = Texttable()
    rtt_section = Texttable()
    rootCA_section = Texttable()
    httpServer_section = Texttable()
    tls_section = Texttable()

    # table headers
    domain_section.set_cols_align(["l", "l"])
    domain_section.set_cols_width([30, 50])
    domain_section.add_row(["Domain", "Scan Results"])

    rtt_section.set_cols_align(["l", "l", "l"])
    rtt_section.add_row(["Domain", "Min RTT (ms)", "Max RTT (ms)"])

    rootCA_section.set_cols_align(["l", "l"])
    rootCA_section.add_row(["Root CA", "Count"])

    httpServer_section.set_cols_align(["l", "l"])
    httpServer_section.add_row(["HTTP Server", "Count"])

    tls_section.set_cols_align(["l", "l"])
    tls_section.add_row(["Feature", "Percentage"])

    # stats initalizing
    rootCA_counts = {}
    httpServer_counts = {}
    tls_versions = {}
    insecure_http_count = 0
    redirect_to_https_count = 0
    hsts_count = 0
    ipv6_count = 0
    rtt_collection = []

    for domain, results in data.items():
        domain_section.add_row([domain, json.dumps(results, indent=2)])

        if "rtt_range" in results and results["rtt_range"]:
            rtt_collection.append([domain, results["rtt_range"][0], results["rtt_range"][1]])

        if "root_ca" in results and results["root_ca"]:
            root_ca = results["root_ca"]
            rootCA_counts[root_ca] = rootCA_counts.get(root_ca, 0) + 1

        if "http_server" in results and results["http_server"]:
            http_server = results["http_server"]
            httpServer_counts[http_server] = httpServer_counts.get(http_server, 0) + 1

        if "tls_versions" in results:
            for version in results["tls_versions"]:
                tls_versions[version] = tls_versions.get(version, 0) + 1

        if "insecure_http" in results and results["insecure_http"]:
            insecure_http_count += 1

        if "redirect_to_https" in results and results["redirect_to_https"]:
            redirect_to_https_count += 1

        if "hsts" in results and results["hsts"]:
            hsts_count += 1

        if "ipv6_addresses" in results and results["ipv6_addresses"]:
            ipv6_count += 1

    rtt_collection.sort(key = lambda x: x[2] - x[1])
    for domain, rtt_start, rtt_end in rtt_collection:
        rtt_section.add_row([domain, rtt_start, rtt_end])

    for root_ca, count in sorted(rootCA_counts.items(), key=lambda x: x[1], reverse=True):
        rootCA_section.add_row([root_ca, count])

    for http_server, count in sorted(httpServer_counts.items(), key=lambda x: x[1], reverse=True):
        httpServer_section.add_row([http_server, count])

    # TLS + support for others in part 2
    tls_stats = {
        "SSLv2": tls_versions.get("SSLv2", 0) / len(data) * 100,
        "SSLv3": tls_versions.get("SSLv3", 0) / len(data) * 100,
        "TLSv1.0": tls_versions.get("TLSv1.0", 0) / len(data) * 100,
        "TLSv1.1": tls_versions.get("TLSv1.1", 0) / len(data) * 100,
        "TLSv1.2": tls_versions.get("TLSv1.2", 0) / len(data) * 100,
        "TLSv1.3": tls_versions.get("TLSv1.3", 0) / len(data) * 100,
        "plain http": insecure_http_count / len(data) * 100,
        "https redirect": redirect_to_https_count / len(data) * 100,
        "hsts": hsts_count / len(data) * 100,
        "ipv6": ipv6_count / len(data) * 100
    }

    for feature, percentage in tls_stats.items():
        tls_section.add_row([feature, f"{percentage:.2f}%"])

    with open(out_file, "w") as f:
        f.write("=== Domain Scan Results ===\n")
        f.write(domain_section.draw() + "\n\n")

        f.write("=== RTT Ranges (Fastest to Slowest) ===\n")
        f.write(rtt_section.draw() + "\n\n")

        f.write("=== Root CA Popularity ===\n")
        f.write(rootCA_section.draw() + "\n\n")

        f.write("=== HTTP Server Popularity ===\n")
        f.write(httpServer_section.draw() + "\n\n")

        f.write("=== TLS and Support Statistics for Part 2(e, f, g, c) ===\n")
        f.write(tls_section.draw() + "\n")

def main(in_file, out_file):
    with open(in_file, "r") as f:
        data = json.load(f)
    generate_report(data, out_file)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    main(in_file, out_file)