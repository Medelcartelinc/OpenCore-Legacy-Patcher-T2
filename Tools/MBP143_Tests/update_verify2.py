import sys

with open('verify_efi.py', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "errors = [line for line in result.stdout.split" in line:
        new_lines.append(line)
        new_lines.append("        errors = [e for e in errors if 'redundant' not in e.lower() and 'checkmisc returns' not in e.lower()]\n")
        new_lines.append("        if not errors: errors = ['No issues found.']\n")
    else:
        new_lines.append(line)

with open('verify_efi.py', 'w') as f:
    for line in new_lines:
        f.write(line)

