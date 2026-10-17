# Constellation Inventory

One file, `constellation.py`, that lists every component an AI agent depends on (model, harness, MCP servers, plugins, tools, prompts, memory, datasets, runtime, credential references) with versions and content hashes, and writes the list as a CycloneDX 1.6 AIBOM.

It is the inventory step of VCRI's agent reconciliation model, on its own. It does not score or rate anything.

## Built to be approved, not trusted

The whole tool is one file of about 400 lines, written to be read in a sitting.

- Python standard library only, Python 3.8 or later. Nothing to install.
- No network access of any kind.
- Runs no other programs: no subprocess, no shell, no eval.
- Reads only the paths in your manifest. With `--discover` it also reads a fixed, listed set of MCP client config files (`DISCOVERY_PATHS` near the top of the file), and nothing else.
- Never writes secret values. For discovered MCP servers it keeps the command's basename, the transport, the URL host, environment variable names (not values), and a SHA-256 of the argument list (not the arguments). Credentials are references: a name and a scope.
- Writes only the output file you name.

## Use

```
python3 constellation.py init > manifest.json        # starter manifest; edit it
python3 constellation.py build manifest.json --out aibom.cdx.json
python3 constellation.py build manifest.json --discover --out aibom.cdx.json
python3 constellation.py check aibom.cdx.json        # missing versions, suppliers, hashes
python3 constellation.py diff  last.cdx.json aibom.cdx.json   # drift since last time
```

Manifests can be JSON (any Python 3.8+) or TOML (Python 3.11+).

A `path` can be a file or a directory. Directories get a deterministic tree hash (sorted relative paths plus each file's SHA-256). Symlinks are recorded by their target and not followed, so the hash never leaves the directory you named.

## What the output tells you, and what it cannot

Each component carries `vcri:evidence`:

- `observed`: the tool hashed the bytes on disk, or read the entry from a client config file.
- `stated`: someone typed it into the manifest and nothing on disk was checked. A hosted model is always stated, because its weights are not on your disk.

`check` reports gaps against the fields each role needs. It can only check what was listed. An inventory that misses a component looks complete, which is why `--discover` exists, and why the manifest should be owned by the person accountable for the agent.

`diff` exits 1 if anything was added, removed, re-versioned, or re-hashed. Run it on a schedule against the last approved AIBOM and you have a drift alarm.

## Status

v0.1.0, 2026-10-16. Output validates against the CycloneDX 1.6 JSON schema (strict). Run on Python 3.12 and 3.14; the source parses under the Python 3.8 grammar, but has not been run on a 3.8 interpreter yet.

The Value Chain Risk Institute. Code under Apache-2.0. Marpet-Viktor.
