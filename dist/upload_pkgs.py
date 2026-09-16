import urllib.request, json, subprocess, sys, os

res = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n", capture_output=True, text=True)
lines = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
token = lines.get("password")

repo = "Medelcartelinc/OpenCore-Legacy-Patcher-T2"
url = f"https://api.github.com/repos/{repo}/releases"
tag_name = "4.0.0.18009.12"

# Find existing release
req_get = urllib.request.Request(url, headers={
    "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"
})
with urllib.request.urlopen(req_get) as resp_get:
    releases = json.loads(resp_get.read().decode())
    release = None
    for r in releases:
        if r.get("tag_name") == tag_name and not r.get("draft"):
            release = r
            break
            
if not release:
    print("Release not found, creating it...")
    data = json.dumps({
        "tag_name": tag_name,
        "name": f"OpenCore Legacy Patcher T2 (Tahoe Beta) - Stable {tag_name}",
        "body": "This release incorporates the latest upstream updates from `albert-mueller` (including GUI updates and fixes) along with critical workarounds for macOS Tahoe and T2/T1 hardware, plus a specific bugfix for `MetallibSupportPkg` paths.",
        "draft": False,
        "prerelease": False
    }).encode("utf-8")
    req_create = urllib.request.Request(url, data=data, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req_create) as resp_create:
        release = json.loads(resp_create.read().decode())

release_id = release["id"]
print(f"Using existing release {release_id} at {release['html_url']}")

# Delete existing assets
req_assets = urllib.request.Request(f"{url}/{release_id}/assets", headers={
    "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"
})
with urllib.request.urlopen(req_assets) as resp_assets:
    assets = json.loads(resp_assets.read().decode())
    for a in assets:
        req_del_a = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/assets/{a['id']}", method="DELETE", headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"
        })
        urllib.request.urlopen(req_del_a)
        print(f"Deleted old asset {a['name']}")
        
upload_url = release["upload_url"].split("{")[0]

# We are uploading the 3 individual PKGs instead of the ZIP
assets = [
    "dist/OpenCore-Patcher-T2.pkg",
    "dist/AutoPkg-Assets-T2.pkg",
    "dist/OpenCore-Patcher-Uninstaller.pkg"
]

for file_name in assets:
    if os.path.exists(file_name):
        base_name = os.path.basename(file_name)
        print(f"Uploading {base_name}...")
        url_up = upload_url + f"?name={base_name}"
        with open(file_name, "rb") as f:
            dmg_data = f.read()
        req2 = urllib.request.Request(url_up, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/octet-stream",
            "Accept": "application/vnd.github+json"
        }, data=dmg_data)
        with urllib.request.urlopen(req2) as resp2:
            asset = json.loads(resp2.read().decode())
            print(f"Asset {file_name} uploaded! Link: {asset['browser_download_url']}")
    else:
        print(f"Error: {file_name} not found!")
