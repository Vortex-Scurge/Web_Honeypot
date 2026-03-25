import re
import logging

def clean_payload(payload):
    """Normalize and clean a raw payload string."""
    p = payload.strip().lower()
    
    # Skip empty
    if not p:
        return None
        
    # Skip overly long payloads (likely noise or specific monolithic exploits we don't need for generic matching)
    if len(p) > 250:
        return None
        
    # Skip markdown artifacts or tool commands
    if p.startswith('```') or p.startswith('http://') or p.startswith('https://') or p.startswith('curl '):
        return None
        
    # Skip too short payloads which cause false positives
    if len(p) < 5:
        return None
        
    return p

def merge_and_clean_datasets(crs_patterns, raw_payloads, max_limit=1000):
    """
    Merges regex patterns from CRS with raw payloads from PayloadsAllTheThings.
    Converts raw payloads to regex safely. Removes duplicates and limits size.
    """
    final_patterns = set()
    
    # 1. Add CRS patterns directly (they are already regexes)
    for pat in crs_patterns:
        if pat and 5 < len(pat) < 500: # Sanity check length and avoid too generic regexes like "="
            final_patterns.add(pat)
            
    # 2. Add PayloadsAllTheThings payloads (need escaping to be safe regexes)
    cleaned_payloads = set()
    for raw in raw_payloads:
        cleaned = clean_payload(raw)
        if cleaned:
            cleaned_payloads.add(cleaned)
            
    for p in cleaned_payloads:
        # Convert the exact payload string into a regex pattern
        # This ensures our engine can match it anywhere in the request
        safe_regex = re.escape(p)
        final_patterns.add(safe_regex)
        
    # Convert to list and apply limit
    merged_list = list(final_patterns)
    
    if len(merged_list) > max_limit:
        logging.info(f"Limiting dataset from {len(merged_list)} to {max_limit} patterns.")
        merged_list = merged_list[:max_limit]
        
    return merged_list
