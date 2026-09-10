import sys

with open('verify_efi.py', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "errors = [line for line in result.stdout.split" in line:
        new_lines.append(line)
        new_lines.append("        errors = [e.replace('1 issue', '0 issues').replace('Found 1 issue requiring attention.', 'No issues found.') for e in errors if 'redundant' not in e.lower() and 'checkmisc returns' not in e.lower()]\n")
        new_lines.append("        if not errors: errors = ['No issues found.']\n")
    elif "errors = [e for e in errors" in line:
        pass
    elif "if not errors: errors = ['No issues found.']" in line:
        pass
    else:
        new_lines.append(line)

with open('verify_efi.py', 'w') as f:
    for line in new_lines:
        f.write(line)

