import json, re

# The Command Injection dataset generated some extremely generic regex like `\s` and `/`
# Let's purge patterns under length 10 or patterns that are just simple symbols.

def filter_dataset(file_path):
    try:
        data = json.load(open(file_path))
        new_patterns = []
        for p in data['patterns']:
            # Reject if too short (unless it's a known short exploit)
            if len(p) < 12:
                continue
            
            # Reject if it's literally just symbols
            if not re.search(r'[a-zA-Z0-9]', p):
                continue
                
            new_patterns.append(p)
            
        data['patterns'] = new_patterns
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Filtered {file_path}. Now has {len(new_patterns)} patterns.")
    except Exception as e:
        print(f"Error filtering {file_path}: {e}")

filter_dataset('datasets/command_injection.json')
filter_dataset('datasets/sql_injection.json')
filter_dataset('datasets/xss.json')
filter_dataset('datasets/lfi.json')
filter_dataset('datasets/sensitive_file.json')
