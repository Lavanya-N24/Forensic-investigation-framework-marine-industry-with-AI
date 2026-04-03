import sys
import re

# CTF Challenge: "The 66th Key"
# Every byte in the file was XOR'd with 0x42 (66 decimal)
# We XOR it back to recover the original ELF binary

input_file = sys.argv[1] if len(sys.argv) > 1 else "heartbeat"

with open(input_file, "rb") as f:
    data = f.read()

# XOR every byte with 0x42
decoded = bytes([b ^ 0x42 for b in data])

# Write decoded binary
output_file = input_file + "_decoded"
with open(output_file, "wb") as f:
    f.write(decoded)

print(f"Decoded file written to: {output_file}")
print(f"File size: {len(decoded)} bytes")
print(f"First 4 bytes: {decoded[:4]}")

# Search for flag pattern in the decoded binary
text = decoded.decode("latin-1")
flags = re.findall(r'Flag\{[^}]*\}', text, re.IGNORECASE)
if flags:
    print(f"\n*** FLAG FOUND: {flags[0]} ***")
else:
    # Also try searching for common flag patterns
    flags2 = re.findall(r'flag\{[^}]*\}', text, re.IGNORECASE)
    if flags2:
        print(f"\n*** FLAG FOUND: {flags2[0]} ***")
    else:
        # Print all printable strings of length > 4
        print("\nNo flag pattern found directly. Extracting strings...")
        strings = re.findall(rb'[\x20-\x7e]{5,}', decoded)
        print("\n--- Interesting strings ---")
        for s in strings:
            s_decoded = s.decode('ascii', errors='ignore')
            if any(kw in s_decoded.lower() for kw in ['flag', 'ctf', 'key', 'heart', 'secret', 'hidden']):
                print(f"  >> {s_decoded}")
        print("\n--- All strings ---")
        for s in strings:
            print(f"  {s.decode('ascii', errors='ignore')}")
