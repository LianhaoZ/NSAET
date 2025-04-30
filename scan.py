import json
import time
import subprocess
import sys
import socket
import maxminddb

def scan_domains(domains):
    res = {}
    for domain in domains:
        d_r = {"scan_time": time.time()}
 
        ipv4_addr = get_addresses(domain, "-type=A")
        if ipv4_addr:
            d_r["ipv4_addresses"] = ipv4_addr
 
        ipv6_addr = get_addresses(domain, "-type=AAAA")
        if ipv6_addr is not None:
            d_r["ipv6_addresses"] = ipv6_addr
 
        http_s = get_http_server(domain)
        if http_s != -1:
            d_r["http_server"] = http_s 

        insecure_http = check_insecure_http(domain)
        if insecure_http is not None:
            d_r["insecure_http"] = insecure_http

        redirect_to_https = check_redirect_to_https(domain)
        if redirect_to_https is not None:
            d_r["redirect_to_https"] = redirect_to_https

        hsts = check_hsts(domain)
        if hsts is not None:
            d_r["hsts"] = hsts

        tls_v = get_tls_versions(domain)
        if tls_v:
            d_r["tls_versions"] = tls_v

        root_ca = get_root_ca(domain)
        if root_ca != -1:
            d_r["root_ca"] = root_ca

        rdns_n = get_rdns_names(ipv4_addr)
        if rdns_n:
            d_r["rdns_names"] = rdns_n

        rtt_r = get_rtt_range(ipv4_addr)
        if rtt_r:
            d_r["rtt_range"] = rtt_r

        geo_l = get_geo_locations(ipv4_addr)
        if geo_l:
            d_r["geo_locations"] = geo_l

        res[domain] = d_r
    return res

def get_addresses(domain, type):
    dns = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "94.140.14.14", "185.228.168.9", "76.76.2.0", "76.76.19.19", "129.105.49.1", "74.82.42.42", "205.171.3.65","193.110.81.0", "147.93.130.20", "51.158.108.203"]
    ip_addresses = []
    seen = set()
    for server in dns:
        try:
            result = subprocess.check_output(["nslookup", type, domain, server], timeout=0.15, stderr=subprocess.STDOUT).decode("utf-8")
            for line in result.splitlines():
                if "Address:" in line and not line.strip().startswith("#") and "#" not in line:
                    ip = line.split()[-1]
                    if ((type == "-type=A" and "." in ip) or (type == "-type=AAAA" and ":" in ip)) and ip not in seen:
                        ip_addresses.append(ip)
                        seen.add(ip)
        except subprocess.TimeoutExpired:
            if type == "-type=A":
                print(f"Timed out getting IPv4 addresses for {domain} using dns: {server}", file=sys.stderr)
            else:
                print(f"Timed out getting IPv6 addresses for {domain} using dns: {server}", file=sys.stderr)
            continue
        except Exception as e:
            if type == "-type=A":
                print(f"Error getting IPv4 addresses for {domain}: {e}", file=sys.stderr)
            else:
                print(f"Error getting IPv6 addresses for {domain}: {e}", file=sys.stderr)
            continue
    return ip_addresses

def get_http_server(domain):
    try:
        result = subprocess.check_output(["curl", "-I", f"http://{domain}"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        for line in result.splitlines():             
            if line.startswith("Server:"):
                return line.split(":", 1)[1].strip()
        return None
    except subprocess.TimeoutExpired:
        return -1
    except Exception as e:
        print(f"Error getting HTTP server for {domain}: {e}", file=sys.stderr)
        return -1

def check_insecure_http(domain):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((domain, 80))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error checking insecure HTTP for {domain}: {e}", file=sys.stderr)
        return None

def check_redirect_to_https(domain):
    try:
        result = subprocess.check_output(["curl", "-I", f"http://{domain}"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        for line in result.splitlines():
            if line.startswith("Location:") and "https://" in line:
                return True
        return False
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Error checking redirect to HTTPS for {domain}: {e}", file=sys.stderr)
        return None

def check_hsts(domain):
    def get_final_url(domain):
        try:
            url = f"http://{domain}"
            while True:
                result = subprocess.check_output(["curl", "-I", url], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                location = next((line.split()[1] for line in result.splitlines() if line.startswith("Location:") and "https://" in line), None)
                if not location:
                    return url
                url = location
        except subprocess.TimeoutExpired:
            return f"http://{domain}"
        except Exception as e:
            print(f"Error checking redirect to HTTPS for {domain}: {e}", file=sys.stderr)
            return f"http://{domain}"

    url = get_final_url(domain)
    try:
        result = subprocess.check_output(["curl", "-I", url], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        return any(line.startswith("Strict-Transport-Security:") for line in result.splitlines())
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Error checking HSTS for {domain}: {e}", file=sys.stderr)
        return None

def get_tls_versions(domain):
    tls_versions = []
    tls_v = {"tls1": "TLSv1.0", "tls1_1": "TLSv1.1", "tls1_2": "TLSv1.2", "tls1_3": "TLSv1.3", "ssl2": "SSLv2", "ssl3": "SSLv3"}
    for version in ["tls1", "tls1_1", "tls1_2", "tls1_3"]:
        try:
            result = subprocess.check_output(["openssl", "s_client", f"-{version}", "-connect", f"{domain}:443"], input=b"", timeout=2, stderr=subprocess.STDOUT)
            if b"CONNECTED" in result:
                tls_versions.append(tls_v[version])
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            print(f"Error checking TLS version {version} for {domain}: {e}", file=sys.stderr)

    try:
        result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        for version in ["ssl2", "ssl3"]:
            if f"{tls_v[version]}" in result:
                tls_versions.append(tls_v[version])
    except subprocess.TimeoutExpired:
        print(f"Timed out checking ssl version for {domain}", file=sys.stderr)
    except Exception as e:
        print(f"Error checking ssl version for {domain}: {e}", file=sys.stderr)
    
    return tls_versions

def get_root_ca(domain):
    try:
        result = subprocess.check_output(["openssl", "s_client", "-connect", f"{domain}:443"], input=b"", timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        for line in result.splitlines():
            if "O =" in line:
                return line.split("O =")[1].strip().strip(",").split(',')[0]
        return None
    except subprocess.TimeoutExpired:
        return -1
    except Exception as e:
        print(f"Error getting root CA for {domain}: {e}", file=sys.stderr)
        return -1

def get_rdns_names(ipv4_addresses):
    if not ipv4_addresses: 
        return []
    rdns_names = []
    for ip in ipv4_addresses:
        try:
            result = subprocess.check_output(["nslookup", ip], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            for line in result.splitlines():
                if "name =" in line:
                    rdns_names.append(line.split("name =")[1].strip())
        except subprocess.TimeoutExpired:
            continue
        except Exception as e:
            print(f"Error getting reverse DNS for {ip}: {e}", file=sys.stderr)
    return rdns_names

def get_rtt_range(ipv4_addresses):
    if not ipv4_addresses: 
        return []
    rtts = []
    for ip in ipv4_addresses:
        for port in [80, 22, 443]:
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                rtt = (time.time() - start_time) * 1000  # ms
                rtts.append(rtt)
                sock.close()
                break
            except Exception as e:
                print(f"Error measuring RTT for {ip}: {e}", file=sys.stderr)
    return [min(rtts), max(rtts)] if rtts else None

def get_geo_locations(ipv4_addresses):
    if not ipv4_addresses: 
        return []
    geo_locations = set()
    with maxminddb.open_database("GeoLite2-City.mmdb") as reader:
        for ip in ipv4_addresses:
            try:
                location = reader.get(ip)
                if location:
                    city = location.get("city", {}).get("names", {}).get("en", "Unknown")
                    region = location.get("subdivisions", [{}])[0].get("names", {}).get("en", "Unknown")
                    country = location.get("country", {}).get("names", {}).get("en", "Unknown")
                    geo_locations.add(f"{city}, {region}, {country}")
            except Exception as e:
                print(f"Error getting geo location for {ip}: {e}", file=sys.stderr)
    return list(geo_locations)

def main(in_file, out_file):
    with open(in_file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]
        
    res = scan_domains(domains)
    with open(out_file, "w") as f:
        json.dump(res, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    main(in_file, out_file)