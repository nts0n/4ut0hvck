import argparse
import sys
import subprocess
import os
import re
import requests

# Color codes
RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m' 
CYAN = "\033[36m"
END = "\033[0m"



def banner():
    font = f""" {BLUE}
 ▄▄▄       █    ██ ▄▄▄█████▓ ██░ ██  ██▒   █▓ ▄████▄   ██ ▄█▀
▒████▄     ██  ▓██▒▓  ██▒ ▓▒▓██░ ██▒▓██░   █▒▒██▀ ▀█   ██▄█▒ 
▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██▀▀██░ ▓██  █▒░▒▓█    ▄ ▓███▄░ 
░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░▓█ ░██   ▒██ █░░▒▓▓▄ ▄██▒▓██ █▄ 
 ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░▓█▒░██▓   ▒▀█░  ▒ ▓███▀ ░▒██▒ █▄
 ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░    ▒ ░░▒░▒   ░ ▐░  ░ ░▒ ▒  ░▒ ▒▒ ▓▒
  ▒   ▒▒ ░░░▒░ ░ ░     ░     ▒ ░▒░ ░   ░ ░░    ░  ▒   ░ ░▒ ▒░
  ░   ▒    ░░░ ░ ░   ░       ░  ░░ ░     ░░  ░        ░ ░░ ░ 
      ░  ░   ░               ░  ░  ░      ░  ░ ░      ░  ░   
                                         ░   ░               

                                    v1.0 by Pr1vacy     
                                         """
    print(font)



def run_subdomain_tools(input_file, output_dir):
    subfinder_out = os.path.join(output_dir, "subdomain")
    subdominator_out = os.path.join(output_dir, "subdomain2")
    allsubdomain_out = os.path.join(output_dir, "allsubdomain")

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Run subfinder
    commands = [
        (["subfinder", "-dL", input_file, "-o", subfinder_out], "Running subfinder..."),
        (["subdominator", "-dL", input_file, "-o", subdominator_out], "Running subdominator...")
    ]

    for cmd, msg in commands:
        print(f"{CYAN}{msg}{END} {' '.join(cmd)}")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"{GREEN}Completed: {' '.join(cmd)}{END}")
        else:
            print(f"{RED}Failed: {' '.join(cmd)}{END}")
            print(result.stderr.decode())
            sys.exit(1)

    # Read and combine results
    unique_domains = set()
    for fname in [subfinder_out, subdominator_out]:
        if os.path.exists(fname):
            with open(fname, "r") as f:
                for line in f:
                    unique_domains.add(line.strip())

    # Save all unique domains
    with open(allsubdomain_out, "w") as f:
        for domain in sorted(unique_domains):
            f.write(domain + "\n")

    print(f"{GREEN}All unique subdomains saved to: {allsubdomain_out}{END}")

    # Print the list of all subdomains
    print(f"{YELLOW}Subdomain list:{END}")
    with open(allsubdomain_out, "r") as f:
        for line in f:
            print(line.strip())


def run_httpx_toolkit(input_file, output_dir):
    allsubdomain_path = os.path.join(output_dir, "allsubdomain")
    alivewtech_path = os.path.join(output_dir, "alivewtech.txt")
    allalive_path = os.path.join(output_dir, "allAlive.txt")

    # Determine input for httpx-toolkit
    if os.path.exists(allsubdomain_path) and os.path.getsize(allsubdomain_path) > 0:
        httpx_input = allsubdomain_path
    else:
        # If allsubdomain doesn't exist or is empty, use input_file
        httpx_input = input_file

    # Run httpx-toolkit
    cmd = [
        "httpx-toolkit",
        "-l", httpx_input,
        "-ports", "80,443,8080,8000,8888",
        "-td",
        "-sc",
        "-threads", "200",
        "-o", alivewtech_path
    ]
    print(f"{CYAN}Running httpx-toolkit...{END} {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(f"{GREEN}Completed: {' '.join(cmd)}{END}")
    else:
        print(f"{RED}Failed: {' '.join(cmd)}{END}")
        print(result.stderr.decode())
        sys.exit(1)

    # Extract only the URLs using awk and save to allAlive.txt
    awk_cmd = ["awk", "{print $1}", alivewtech_path]
    print(f"{CYAN}Extracting alive URLs with techdetect and statuscode...{END} {' '.join(awk_cmd)}")
    with open(allalive_path, "w") as out_f:
        awk_result = subprocess.run(awk_cmd, stdout=out_f, stderr=subprocess.PIPE)
    if awk_result.returncode == 0:
        print(f"{GREEN}Alive URLs saved to: {allalive_path}{END}")
        # Optionally, print the URLs
        with open(allalive_path, "r") as f:
            for line in f:
                print(line.strip())
    else:
        print(f"{RED}Failed to extract URLs with awk.{END}")
        print(awk_result.stderr.decode())
        sys.exit(1)



#run the crawlers
def run_crawlers(args):
    output_dir = args.output
    allalive_path = os.path.join(output_dir, "allAlive.txt")
    allurls_path = os.path.join(output_dir, "allurls.txt")
    allfile_path = os.path.join(output_dir, "allFile.txt")
    waybackurls_path = os.path.join(output_dir, "waybackURL")
    input_file = args.input

    # 1. Run katana
    if args.httpx:
        katana_input = allalive_path
    else:
        katana_input = input_file

    katana_cmd = [
        "katana",
        "-u", katana_input,
        "-d", "5",
        "-kf",
        "-jc",
        "-fx",
        "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg",
        "-o", allurls_path
    ]
    print(f"{CYAN}Running katana crawler...{END} {' '.join(katana_cmd)}")
    result = subprocess.run(katana_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        print(f"{GREEN}Completed: {' '.join(katana_cmd)}{END}")
    else:
        print(f"{RED}Failed: {' '.join(katana_cmd)}{END}")
        print(result.stderr.decode())
        sys.exit(1)

    # Extract secret files from allurls.txt
    secret_pattern = re.compile(
        r"\.xls$|\.xml$|\.xlsx$|\.json$|\.php$|\.asp$|\.pdf$|\.sql$|\.doc$|\.docx$|\.pptx$|\.txt$|\.zip$|\.tar\.gz$|\.tgz$|\.bak$|\.7z$|\.rar$|\.log$|\.cache$|\.secret$|\.db$|\.backup$|\.yml$|\.gz$|\.config$|\.csv$|\.yaml$|\.md$|\.md5$|\.exe$|\.dll$|\.bin$|\.ini$|\.bat$|\.sh$|\.tar$|\.deb$|\.git$|\.env$|\.rpm$|\.iso$|\.img$|\.apk$|\.msi$|\.dmg$|\.tmp$|\.crt$|\.pem$|\.key$|\.pub$|\.asc$|\.asp$|\.aspx$|\.jspx$|\.jsp$",
        re.IGNORECASE
    )
    print(f"{CYAN}Extracting secret files from katana output...{END}")
    with open(allurls_path, "r") as infile, open(allfile_path, "w") as outfile:
        for line in infile:
            if secret_pattern.search(line.strip()):
                outfile.write(line)
    print(f"{GREEN}Secret files saved to: {allfile_path}{END}")

    # 2. Run waybackurls
    if args.subdomain:
        with open(input_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
        all_wayback_urls = []
        for idx, domain in enumerate(domains):
            params = {
                "url": f"*.{domain}/*",
                "collapse": "urlkey",
                "output": "text",
                "fl": "original"
            }
            print(f"{CYAN}Requesting waybackurls for {domain}...{END}")
            try:
                resp = requests.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=30)
                if resp.status_code == 200:
                    urls = resp.text.strip().splitlines()
                    all_wayback_urls.extend(urls)
                    print(f"{GREEN}Waybackurls completed for {domain} ({len(urls)} URLs){END}")
                else:
                    print(f"{RED}Waybackurls failed for {domain} (HTTP {resp.status_code}){END}")
            except Exception as e:
                print(f"{RED}Waybackurls failed for {domain}: {e}{END}")
        # Save all waybackurls to file
        with open(waybackurls_path, "w") as outfile:
            for url in all_wayback_urls:
                outfile.write(url + "\n")
        print(f"{GREEN}All waybackurls saved to: {waybackurls_path}{END}")





def argument():
    parser = argparse.ArgumentParser(description="tool for auto recon and run tool for pentesting.")
    parser.add_argument('-i', '--input', type=str, help='Path to input file')
    parser.add_argument('-o', '--output', type=str, help='Output directory')
    parser.add_argument('-s', '--subdomain', action='store_true', help='Enable subdomain enumeration function')
    parser.add_argument('-H', '--httpx', action='store_true', help='Check alive domain, tech, statuscode')
    parser.add_argument('-c', '--crawl', action='store_true', help='Enable crawling (katana, waybackurls)')
    parser.add_argument('-n', '--nuclei', action='store_true', help='Enable nuclei scanning')
    # Add more arguments as needed
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    banner()
    args = argument()
    if args.subdomain:
        if not args.input or not args.output:
            print(f"{RED}Error: --input and --output are required for subdomain enumeration.{END}")
            sys.exit(1)
        run_subdomain_tools(args.input, args.output)
    if args.httpx:
        if not args.input or not args.output:
            print(f"{RED}Error: --input and --output are required for httpx-toolkit.{END}")
            sys.exit(1)
        run_httpx_toolkit(args.input, args.output)
    if args.crawl:
        if not args.input or not args.output:
            print(f"{RED}Error: --input and --output are required for crawling.{END}")
            sys.exit(1)
        run_crawlers(args)