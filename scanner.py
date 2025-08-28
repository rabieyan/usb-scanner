#!/usr/bin/env python3
import argparse, csv, hashlib, json, os, re, subprocess, sys
from datetime import datetime, timezone

try:
    import magic
except Exception:
    magic = None

SUSPICIOUS_EXT = {
    # Executables/scripts
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".jar",
    # Shortcuts/autorun
    ".lnk", ".inf",
    # Office/PDF that can carry macros or JS
    ".doc", ".docm", ".dotm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf",
    # Archives
    ".zip", ".rar", ".7z", ".iso",
}

DOUBLE_EXT_RE = re.compile(r".+\.(?:jpg|png|pdf|doc|txt)\.(exe|scr|js|vbs|cmd|bat)$", re.I)

def sha256(path, bufsize=1024*1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b: break
            h.update(b)
    return h.hexdigest()

def filetype(path):
    if magic:
        try:
            return magic.from_file(path)
        except Exception:
            return ""
    # Fallback to `file`
    try:
        out = subprocess.check_output(["file", "-b", path], text=True, stderr=subprocess.DEVNULL).strip()
        return out
    except Exception:
        return ""

def is_hidden(path):
    name = os.path.basename(path)
    return name.startswith(".") or name.startswith("_") or name.lower() in {"autorun.inf"}

def suspicious_heuristics(path, ftype, st):
    flags = []

    name = os.path.basename(path)
    lower = name.lower()

    # 1) Double extensions like invoice.pdf.exe
    if DOUBLE_EXT_RE.match(lower):
        flags.append("double-extension")

    # 2) Suspicious extensions
    ext = os.path.splitext(lower)[1]
    if ext in SUSPICIOUS_EXT:
        flags.append(f"extension:{ext}")

    # 3) Executable bits on text or script files
    if (st.st_mode & 0o111) and ("text" in ftype.lower() or ext in {".sh", ".py"}):
        flags.append("executable-perms-on-text")

    # 4) Hidden files
    if is_hidden(path):
        flags.append("hidden")

    # 5) Very large or very small binaries
    if "executable" in ftype.lower():
        if st.st_size < 1024:
            flags.append("tiny-executable")
        if st.st_size > 200*1024*1024:
            flags.append("huge-executable")

    # 6) LNK or INF
    if ext == ".lnk":
        flags.append("shortcut-file")
    if lower == "autorun.inf":
        flags.append("autorun-file")

    return flags

def run_clamav(path):
    # Use clamscan if present
    try:
        proc = subprocess.run(["clamscan", "--no-summary", path], capture_output=True, text=True, check=False)
        # Output format: "<path>: <result>"
        infected = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.endswith("FOUND"):
                sig = line.rsplit(" ", 1)[0].split(": ", 1)[1]
                infected.append(sig)
        return infected
    except FileNotFoundError:
        return None

def run_yara(path, rules):
    try:
        proc = subprocess.run(["yara", "-r", rules, path], capture_output=True, text=True, check=False)
        hits = []
        for line in proc.stdout.splitlines():
            # format: RULE_NAME <file>
            if line.strip():
                rule = line.split()[0]
                hits.append(rule)
        return hits
    except FileNotFoundError:
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True, help="Path to scan (mounted USB)")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--clamav", action="store_true", help="Force ClamAV scanning (otherwise best-effort)")
    ap.add_argument("--yara-rules", help="Path to YARA rules file or directory")
    args = ap.parse_args()

    records = []
    for root, dirs, files in os.walk(args.path):
        # Skip lost+found or system metadata dirs
        dirs[:] = [d for d in dirs if d not in ("System Volume Information", "$RECYCLE.BIN", "lost+found")]
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                st = os.lstat(fp)
                if not os.path.isfile(fp):
                    continue
                ftype = filetype(fp)
                sha = sha256(fp)
                flags = suspicious_heuristics(fp, ftype, st)

                clam = None
                yara_hits = None

                if args.clamav:
                    clam = run_clamav(fp)
                else:
                    # best-effort try clamscan if available
                    clam = run_clamav(fp)

                if args.yara_rules:
                    yara_hits = run_yara(fp, args.yara_rules)

                rec = {
                    "path": fp,
                    "name": fn,
                    "size": st.st_size,
                    "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                    "sha256": sha,
                    "filetype": ftype,
                    "flags": flags,
                    "clamav": clam or [],
                    "yara": yara_hits or [],
                }
                records.append(rec)
            except Exception as e:
                records.append({
                    "path": fp,
                    "error": str(e),
                    "flags": ["read-error"],
                })

    # Write JSON
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump({"scanned_at_utc": datetime.now(timezone.utc).isoformat(), "items": records}, f, indent=2)

    # Write CSV
    fieldnames = ["path","name","size","mtime_utc","sha256","filetype","flags","clamav","yara"]
    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in records:
            row = {k: r.get(k, "") for k in fieldnames}
            # join list fields
            row["flags"] = ";".join(r.get("flags", [])) if isinstance(r.get("flags"), list) else r.get("flags","")
            row["clamav"] = ";".join(r.get("clamav", [])) if isinstance(r.get("clamav"), list) else r.get("clamav","")
            row["yara"] = ";".join(r.get("yara", [])) if isinstance(r.get("yara"), list) else r.get("yara","")
            w.writerow(row)

if __name__ == "__main__":
    main()