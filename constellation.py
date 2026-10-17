#!/usr/bin/env python3
"""
constellation.py: inventory an AI agent constellation and write it as a CycloneDX 1.6 AIBOM.

An agent constellation is everything an agent depends on, taken as one unit: the model,
the harness, MCP servers, plugins, tools, prompts, memory stores, datasets, the runtime,
and references to the credentials it holds. This tool lists those components with
versions and content hashes. It does not score, rate, or judge anything.

Written to be read in one sitting by the person who has to approve it. Properties:
  - Python standard library only. Python 3.8 or later. No third-party packages.
  - No network access. No sockets, no HTTP, no DNS. Nothing leaves the machine.
  - Runs no other programs. No subprocess, no shell, no eval, no imports of your code.
  - Reads only the files you name in the manifest, plus, ONLY with --discover, a short
    fixed list of MCP client config files (DISCOVERY_PATHS below).
  - Never records secret values. Environment variable VALUES and command-line arguments
    of discovered MCP servers are not written; env var names and an args hash are.
    Credentials are recorded as references (name, scope), never the secret.
  - Writes only the output file you name (default: stdout).

Commands:
  constellation.py init  [--format json|toml] > manifest.json   write a starter manifest
  constellation.py build manifest.json [--discover] [--out aibom.cdx.json]
  constellation.py check aibom.cdx.json [--strict]             list missing versions/hashes
  constellation.py diff  old.cdx.json new.cdx.json              what changed (agent drift)

Evidence class per component (VCRI's Observed / Recorded / Stated), in the property
vcri:evidence:
  observed  the tool hashed the bytes on disk, or read the entry from a client config file
  stated    the manifest author typed it and nothing on disk was checked

License: Apache-2.0. The Value Chain Risk Institute. Marpet-Viktor.
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
import uuid

TOOL_NAME = "vcri-constellation-inventory"
TOOL_VERSION = "0.1.0"
NS = "vcri"  # property namespace

# Manifest role -> CycloneDX 1.6 component type.
ROLE_TYPES = {
    "model": "machine-learning-model",
    "harness": "framework",
    "mcp-server": "application",
    "plugin": "library",
    "tool": "application",
    "library": "library",
    "prompt": "data",
    "memory": "data",
    "dataset": "data",
    "runtime": "platform",
    "container": "container",
    "credential": "data",
}

# Fields check() expects per role. "hash" means a content hash, which needs a path.
REQUIRED = {
    "model": ["version", "supplier", "hash"],
    "harness": ["version"],
    "mcp-server": ["version", "hash"],
    "plugin": ["version", "hash"],
    "tool": ["version"],
    "library": ["version"],
    "prompt": ["hash"],
    "memory": [],
    "dataset": ["version"],
    "runtime": ["version"],
    "container": ["version", "hash"],
    "credential": ["scope"],
}

# --discover reads these and nothing else. "~" is the user's home directory.
# Each entry: (client name, path, key holding the server map).
DISCOVERY_PATHS = [
    ("claude-desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-desktop", "~/.config/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-desktop", "%APPDATA%/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-code", "./.mcp.json", "mcpServers"),
    ("cursor", "~/.cursor/mcp.json", "mcpServers"),
    ("cursor", "./.cursor/mcp.json", "mcpServers"),
    ("vscode", "./.vscode/mcp.json", "servers"),
    ("windsurf", "~/.codeium/windsurf/mcp_config.json", "mcpServers"),
]

STARTER = {
    "agent": {
        "name": "example-agent",
        "version": "1.0.0",
        "owner": "team or person accountable for this agent",
        "description": "what the agent does, in one line",
    },
    "components": [
        {"role": "model", "name": "model-name", "version": "exact version or snapshot id",
         "supplier": "who published the weights", "path": "/path/to/weights.safetensors",
         "notes": "for a hosted model with no local weights, omit path; it will be 'stated'"},
        {"role": "harness", "name": "agent framework", "version": "x.y.z"},
        {"role": "mcp-server", "name": "server name", "version": "x.y.z",
         "path": "/path/to/server/dir-or-file"},
        {"role": "plugin", "name": "plugin name", "version": "x.y.z", "path": "/path/to/plugin"},
        {"role": "prompt", "name": "system prompt", "path": "/path/to/system-prompt.txt"},
        {"role": "memory", "name": "vector store", "version": "x.y.z", "path": "/path/to/store"},
        {"role": "runtime", "name": "python", "version": "3.11.9"},
        {"role": "credential", "name": "service account the agent uses",
         "scope": "what it can reach; never the secret itself"},
    ],
}


# ---------------- hashing ----------------

def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_tree(root):
    """Deterministic hash of a directory: sorted relative paths and their file hashes.
    Symlinks are recorded by their target text, not followed, so the hash cannot
    wander outside the directory you named."""
    h = hashlib.sha256()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                entry = "L " + rel + " -> " + os.readlink(full)
            else:
                entry = "F " + rel + " " + sha256_file(full)
                count += 1
            h.update(entry.encode("utf-8") + b"\n")
    return h.hexdigest(), count


def hash_path(path):
    """Returns (hash dict or None, note)."""
    p = os.path.expanduser(os.path.expandvars(path))
    if os.path.isfile(p):
        return {"alg": "SHA-256", "content": sha256_file(p)}, "file"
    if os.path.isdir(p):
        digest, n = sha256_tree(p)
        return {"alg": "SHA-256", "content": digest}, "directory tree, %d files" % n
    return None, "path not found: " + path


# ---------------- manifest ----------------

def load_manifest(path):
    with open(path, "rb") as f:
        raw = f.read()
    if path.endswith(".toml"):
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            sys.exit("TOML needs Python 3.11 or later; use a JSON manifest instead.")
        return tomllib.loads(raw.decode("utf-8"))
    return json.loads(raw.decode("utf-8"))


def to_toml(m):
    """Small writer for the starter manifest only (strings, one table, array of tables)."""
    def q(s):
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'
    out = ["[agent]"] + ["%s = %s" % (k, q(v)) for k, v in m["agent"].items()]
    for c in m["components"]:
        out += ["", "[[components]]"] + ["%s = %s" % (k, q(v)) for k, v in c.items()]
    return "\n".join(out) + "\n"


# ---------------- discovery ----------------

def discover_mcp():
    """Read the fixed DISCOVERY_PATHS. Returns (components, sources)."""
    comps, sources = [], []
    for client, raw, key in DISCOVERY_PATHS:
        p = os.path.abspath(os.path.expanduser(os.path.expandvars(raw)))
        if "%APPDATA%" in p or not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as f:
                cfg = json.loads(f.read().decode("utf-8"))
        except (OSError, ValueError) as e:
            sources.append({"client": client, "path": p, "error": str(e)})
            continue
        servers = cfg.get(key) or {}
        sources.append({"client": client, "path": p, "sha256": sha256_file(p), "servers": len(servers)})
        for name in sorted(servers):
            s = servers[name] if isinstance(servers[name], dict) else {}
            args = s.get("args") or []
            comps.append({
                "role": "mcp-server",
                "name": name,
                "version": "",
                "_discovered": {
                    "client": client,
                    "config": p,
                    "transport": s.get("type") or ("http" if s.get("url") else "stdio"),
                    "command": os.path.basename(str(s.get("command", ""))) if s.get("command") else "",
                    "url_host": _host(s.get("url", "")),
                    "args_sha256": hashlib.sha256(json.dumps(args).encode("utf-8")).hexdigest() if args else "",
                    "env_names": ",".join(sorted((s.get("env") or {}).keys())),
                },
            })
    return comps, sources


def _host(url):
    """Host part only; paths and query strings can carry tokens."""
    if not url:
        return ""
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1]


# ---------------- build ----------------

def bom_ref(role, name, i):
    safe = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in name)[:60]
    return "%s:%s:%d" % (role, safe, i)


def prop(name, value):
    return {"name": "%s:%s" % (NS, name), "value": str(value)}


def build_component(c, i):
    role = c.get("role", "")
    if role not in ROLE_TYPES:
        sys.exit("component %d (%s): unknown role %r; use one of %s"
                 % (i, c.get("name", "?"), role, ", ".join(sorted(ROLE_TYPES))))
    name = c.get("name") or "unnamed-%d" % i
    comp = {"type": ROLE_TYPES[role], "bom-ref": bom_ref(role, name, i), "name": name}
    if c.get("version"):
        comp["version"] = str(c["version"])
    if c.get("supplier"):
        comp["supplier"] = {"name": str(c["supplier"])}
    if c.get("description"):
        comp["description"] = str(c["description"])
    props = [prop("role", role)]
    evidence = "stated"

    if c.get("path"):
        h, note = hash_path(c["path"])
        props.append(prop("path", c["path"]))
        props.append(prop("hash-scope", note))
        if h:
            comp["hashes"] = [h]
            evidence = "observed"
    d = c.get("_discovered")
    if d:
        evidence = "observed"
        for k in ("client", "config", "transport", "command", "url_host", "args_sha256", "env_names"):
            if d.get(k):
                props.append(prop("mcp:" + k.replace("_", "-"), d[k]))
    if role == "credential":
        props.append(prop("credential:reference-only", "true"))
        if c.get("scope"):
            props.append(prop("credential:scope", c["scope"]))
    for k in ("notes", "owner", "license", "source"):
        if c.get(k):
            props.append(prop(k, c[k]))
    props.append(prop("evidence", evidence))
    comp["properties"] = props
    return comp


def build(args):
    m = load_manifest(args.manifest)
    agent = m.get("agent") or {}
    items = list(m.get("components") or [])
    sources = []
    if args.discover:
        found, sources = discover_mcp()
        have = {(c.get("role"), c.get("name")) for c in items}
        for f in found:
            if (f["role"], f["name"]) in have:
                for c in items:  # manifest entry wins; attach what discovery saw
                    if (c.get("role"), c.get("name")) == (f["role"], f["name"]):
                        c["_discovered"] = f["_discovered"]
            else:
                items.append(f)
    comps = [build_component(c, i) for i, c in enumerate(items)]
    root_ref = "agent:" + (agent.get("name") or "agent")
    meta_props = [prop("constellation:component-count", len(comps)),
                  prop("constellation:discovery", "on" if args.discover else "off")]
    for s in sources:
        meta_props.append(prop("discovery:source", json.dumps(s, sort_keys=True)))
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION,
                                      "supplier": {"name": "The Value Chain Risk Institute"}}]},
            "component": {"type": "application", "bom-ref": root_ref,
                          "name": agent.get("name", "agent"),
                          "version": str(agent.get("version", "")),
                          "description": agent.get("description", "")},
            "properties": meta_props + ([prop("agent:owner", agent["owner"])] if agent.get("owner") else []),
        },
        "components": comps,
        "dependencies": [{"ref": root_ref, "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    text = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print("wrote %s: %d components" % (args.out, len(comps)), file=sys.stderr)
    else:
        sys.stdout.write(text)
    gaps = find_gaps(bom)
    if gaps:
        print("%d gap(s); run `check` for the list" % len(gaps), file=sys.stderr)


# ---------------- check / diff ----------------

def props_of(c):
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def find_gaps(bom):
    gaps = []
    for c in bom.get("components", []):
        role = props_of(c).get(NS + ":role", "")
        for field in REQUIRED.get(role, []):
            if field == "hash" and not c.get("hashes"):
                gaps.append((c["name"], role, "no content hash (give a path the tool can read)"))
            elif field == "version" and not c.get("version"):
                gaps.append((c["name"], role, "no version"))
            elif field == "supplier" and not c.get("supplier"):
                gaps.append((c["name"], role, "no supplier"))
            elif field == "scope" and NS + ":credential:scope" not in props_of(c):
                gaps.append((c["name"], role, "no scope"))
    return gaps


def check(args):
    with open(args.bom) as f:
        bom = json.load(f)
    comps = bom.get("components", [])
    counts = {}
    for c in comps:
        ev = props_of(c).get(NS + ":evidence", "unknown")
        counts[ev] = counts.get(ev, 0) + 1
    print("%d components: %s" % (len(comps), ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    gaps = find_gaps(bom)
    for name, role, why in gaps:
        print("  GAP  %-12s %-30s %s" % (role, name, why))
    if not gaps:
        print("  no gaps against the required fields")
    print("Note: this checks completeness of what was listed. It cannot know about a component "
          "nobody listed. Run with --discover where MCP clients are in use.")
    sys.exit(1 if (gaps and args.strict) else 0)


def index(bom):
    out = {}
    for c in bom.get("components", []):
        role = props_of(c).get(NS + ":role", c.get("type", ""))
        h = (c.get("hashes") or [{}])[0].get("content", "")
        out[(role, c["name"])] = (c.get("version", ""), h)
    return out


def diff(args):
    with open(args.old) as f:
        a = index(json.load(f))
    with open(args.new) as f:
        b = index(json.load(f))
    changed = 0
    for key in sorted(set(a) | set(b)):
        role, name = key
        if key not in a:
            print("ADDED    %-12s %s %s" % (role, name, b[key][0])); changed += 1
        elif key not in b:
            print("REMOVED  %-12s %s %s" % (role, name, a[key][0])); changed += 1
        elif a[key] != b[key]:
            what = []
            if a[key][0] != b[key][0]:
                what.append("version %s -> %s" % (a[key][0] or "-", b[key][0] or "-"))
            if a[key][1] != b[key][1]:
                what.append("hash %s -> %s" % (a[key][1][:12] or "-", b[key][1][:12] or "-"))
            print("CHANGED  %-12s %s: %s" % (role, name, "; ".join(what))); changed += 1
    print("%d change(s)" % changed)
    sys.exit(1 if changed else 0)


def init(args):
    if args.format == "toml":
        sys.stdout.write(to_toml(STARTER))
    else:
        sys.stdout.write(json.dumps(STARTER, indent=2) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Inventory an AI agent constellation as a CycloneDX 1.6 AIBOM.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="print a starter manifest")
    p.add_argument("--format", choices=["json", "toml"], default="json")
    p.set_defaults(fn=init)
    p = sub.add_parser("build", help="build the AIBOM from a manifest")
    p.add_argument("manifest")
    p.add_argument("--discover", action="store_true", help="also read the fixed list of MCP client configs")
    p.add_argument("--out", help="output file (default stdout)")
    p.set_defaults(fn=build)
    p = sub.add_parser("check", help="list missing versions, suppliers, hashes")
    p.add_argument("bom")
    p.add_argument("--strict", action="store_true", help="exit 1 if any gap")
    p.set_defaults(fn=check)
    p = sub.add_parser("diff", help="compare two AIBOMs (exit 1 if anything changed)")
    p.add_argument("old")
    p.add_argument("new")
    p.set_defaults(fn=diff)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
