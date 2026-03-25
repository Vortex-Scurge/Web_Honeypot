import json, re

def check(target, target_name):
    print(f"Checking {target_name}:")
    for f in ['sensitive_file.json', 'command_injection.json', 'sql_injection.json', 'lfi.json', 'rfi.json', 'xss.json']:
        try:
            d = json.load(open(f"datasets/{f}"))
            for p in d['patterns']:
                try:
                    cp = re.compile(p, re.IGNORECASE)
                    if cp.search(target):
                        print(f"  Matched in {f}: {p}")
                except re.error:
                    pass
        except Exception as e:
            pass

check('/admin/dashboard ', 'Admin Access')
check('/login?next=http://evil.com ', 'Open Redirect')
check('/proxy?url=http://169.254.169.254/latest/meta-data/', 'SSRF')
check('/api/v1/users', 'API Enum')

