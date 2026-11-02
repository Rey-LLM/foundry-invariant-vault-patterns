#!/usr/bin/env python3
"""FoundryGuard: one command for scanning, generating, checking and reporting.

    foundryguard init                 write a commented foundryguard.toml
    foundryguard scan                 Solidity -> foundryguard.json blueprint
    foundryguard gen                  blueprint -> test/foundryguard/<Contract>/ suites
    foundryguard run [--test]         scan + gen (+ forge test on the generated suites)
    foundryguard check                CI: exit 1 when generated suites are missing or stale
    foundryguard report results.json  forge test --json -> Markdown / SARIF

Run it as ``foundryguard`` after ``pipx install .`` or as ``python3 src/cli/foundryguard.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

if __package__:
    from . import injector, parser, reporting
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import injector  # type: ignore
    import parser  # type: ignore
    import reporting  # type: ignore

CONFIG_TEMPLATE = """# FoundryGuard configuration. Every key is optional.

[scan]
# Source dirs to scan (default: src/ or contracts/).
# paths = ["src"]

[generate]
# out = "test/foundryguard"
# actors = 4
# max_amount = "1e24"

[classify]
# Extra function names (exact names, or regexes like "^enter") per value-flow category.
# deposit = ["enter", "join"]
# withdraw = ["leave"]
# stake_in = ["boost"]
# stake_out = ["unboost"]
# reward = ["getPaid"]
# ignore = ["mintFee"]

[targets]
# include = ["MyToken"]       # fuzz contracts that look like plain ERC-20 tokens
# exclude = ["LegacyVault"]

# Per-contract setUp overrides. Token mocks are available by parameter name
# (e.g. `asset` for an `IERC20 asset_` parameter).
# [contracts.MyVault]
# constructor_args = ["address(asset)", "\\"Vault\\"", "\\"vTKN\\""]
# initializer = "initialize"
# initializer_args = ["address(asset)", "address(this)"]
# setup = ["vm.warp(1 days);"]
"""


def _scan(args) -> dict:
    blueprint = parser.scan_from_args(args)
    if getattr(args, "output", None):
        out = Path(args.output) if args.output == "-" or Path(args.output).is_absolute() else Path(args.root) / args.output
        payload = json.dumps(blueprint, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(payload)
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(payload)
    s = blueprint["summary"]
    print(f"foundryguard: {s['contracts']} contract(s) in {s['files_scanned']} file(s) [{blueprint['backend']}] "
          f"deposit={s['deposit_functions']} withdraw={s['withdraw_functions']} stake_lock={s['stake_lock_functions']}",
          file=sys.stderr)
    return blueprint


def cmd_init(args) -> int:
    path = Path(args.root) / parser.CONFIG_FILE
    if path.exists() and not args.force:
        print(f"foundryguard: {path} already exists (use --force)", file=sys.stderr)
        return 1
    path.write_text(CONFIG_TEMPLATE)
    print(f"foundryguard: wrote {path}")
    return 0


def cmd_scan(args) -> int:
    _scan(args)
    return 0


def cmd_gen(args) -> int:
    blueprint = injector.load_blueprint(Path(args.blueprint))
    root = Path(args.root or blueprint.get("root") or ".").resolve()
    return injector.gen_from_args(args, blueprint, parser.load_config(root, args.config), root)


def cmd_run(args, check: bool = False) -> int:
    if check:
        args.check = True
    blueprint = _scan(args)
    root = Path(args.root).resolve()
    rc = injector.gen_from_args(args, blueprint, parser.load_config(root, args.config), root)
    if rc or not getattr(args, "test", False):
        return rc
    forge = shutil.which("forge")
    if not forge:
        print("foundryguard: --test needs `forge` on PATH (https://getfoundry.sh)", file=sys.stderr)
        return 1
    out = args.out or parser.load_config(root, args.config).get("generate", {}).get("out", "test/foundryguard")
    cmd = [forge, "test", "--match-path", f"{out.rstrip('/')}/*", "--show-metrics"]
    print("foundryguard: " + " ".join(cmd), file=sys.stderr)
    return subprocess.call(cmd, cwd=root)


def cmd_report(args) -> int:
    data = reporting.load_forge_json(Path(args.results))
    root = Path(args.root).resolve()
    md = reporting.markdown_from_forge(data)
    if args.md:
        Path(args.md).write_text(md)
    else:
        sys.stdout.write(md)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(reporting.sarif_from_forge(data, root), indent=2) + "\n")
    return 1 if (args.fail_on_failure and reporting.failed_tests(data)) else 0


def build_cli() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="foundryguard", description="Generate Foundry invariant suites for DeFi contracts.")
    ap.add_argument("--version", action="version", version=f"foundryguard {parser.TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="write a commented foundryguard.toml")
    p.add_argument("--root", default=".")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", help="scan Solidity sources into a JSON blueprint")
    parser.add_scan_args(p)
    p.add_argument("-o", "--output", default="foundryguard.json", help="blueprint path, or '-' for stdout")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("gen", help="generate suites from a blueprint")
    p.add_argument("blueprint", nargs="?", default="foundryguard.json")
    p.add_argument("--root")
    p.add_argument("--config")
    injector.add_gen_args(p)
    p.set_defaults(func=cmd_gen)

    for name, check in (("run", False), ("check", True)):
        p = sub.add_parser(name, help="scan + generate" + (" and fail if suites are stale" if check else ""))
        parser.add_scan_args(p)
        injector.add_gen_args(p)
        p.add_argument("-o", "--output", help="also save the blueprint here")
        if not check:
            p.add_argument("--test", action="store_true", help="run forge test on the generated suites afterwards")
        p.set_defaults(func=(lambda a, c=check: cmd_run(a, c)))

    p = sub.add_parser("report", help="turn `forge test --json` output into Markdown / SARIF")
    p.add_argument("results", help="file with `forge test --json` output")
    p.add_argument("--root", default=".")
    p.add_argument("--md", help="write Markdown here (default: stdout)")
    p.add_argument("--sarif", help="write SARIF here")
    p.add_argument("--fail-on-failure", action="store_true", help="exit 1 if any test failed")
    p.set_defaults(func=cmd_report)

    for sp in sub.choices.values():
        sp.add_argument("-v", "--verbose", action="count", default=0)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_cli().parse_args(argv)
    logging.basicConfig(level=logging.WARNING - 10 * min(args.verbose, 2), format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
