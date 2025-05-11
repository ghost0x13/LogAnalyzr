import re
import sys
import pandas as pd

# Regex patterns
patterns = {
    'SQLi': re.compile(r"(\'|\")\s?or\s?.*=.*|(\%27)|(\%22)|(\-\-)|(\%23)|(#)"),
    'XSS': re.compile(r"(<script>|%3Cscript%3E)"),
    'Scanner': re.compile(r"(nmap|nikto|dirbuster|sqlmap)", re.IGNORECASE)
}

def analyze_log(file_path):
    suspicious_entries = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as log:
        for line in log:
            ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            request = re.search(r'\"(GET|POST).*?\"', line)
            time = re.search(r'(.*?)', line)

            for attack, pattern in patterns.items():
                if pattern.search(line):
                    suspicious_entries.append({
                        'IP': ip.group() if ip else '',
                        'Request': request.group() if request else '',
                        'Attack Type': attack,
                        'Timestamp': time.group(1) if time else ''
                    })

    if suspicious_entries:
        df = pd.DataFrame(suspicious_entries)
        print("Suspicious Entries Found:\n", df)
    else:
        print("No suspicious activity found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python loganalyzr.py /path/to/access.log")
        sys.exit(1)
    analyze_log(sys.argv[1])