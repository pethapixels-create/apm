"""Light ``apm install`` Click command.

``cli.py`` dispatches ``apm install`` here. The options, help text and
lifecycle lock are declared without importing the install pipeline, so the
no-op replay (``install/noop_fast_path.py``) decides before the install graph
behind ``commands/install.py`` (about 750 modules) loads. On a miss the
command body, ``commands.install.install``, runs unchanged.
"""

import importlib

import click

from apm_cli.install.insecure_policy import _allow_insecure_host_callback
from apm_cli.install.locking import serialized_lifecycle_unless_fresh_preview

from ..core.target_catalog import target_all_exclusion_help, target_help_fragment
from ..core.target_detection import TargetParamType, install_runtime_option
from ._helpers import explicit_policy_option, trust_transitive_mcp_option


@click.command(
    help="Install APM, MCP, and LSP dependencies (supports APM packages, Claude skills (SKILL.md), and plugin collections (plugin.json); auto-creates apm.yml; use --allow-insecure for http:// packages)",
    short_help="Install APM, MCP, and LSP dependencies",
)
@click.argument("packages", nargs=-1)
@install_runtime_option
@click.option("--exclude", help="Exclude one runtime from the resolved MCP/LSP target set")
@click.option(
    "--only",
    type=click.Choice(["apm", "mcp"]),
    help="Install only APM packages or MCP/LSP service dependencies",
)
@click.option(
    "--update",
    is_flag=True,
    help="Update dependencies to latest Git references (deprecated: prefer 'apm update' for an interactive plan, or 'apm update --yes' for CI). Unlike --refresh, --update restructures the entire dependency graph.",
)
@click.option("--dry-run", is_flag=True, help="Show what would change without writing files")
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite locally-authored files on collision and deploy despite critical security findings (does NOT refresh refs; use 'apm update' for that)",
)
@click.option(
    "--frozen/--no-frozen",
    default=None,
    help=(
        "Refuse to install when apm.lock.yaml is missing or out of sync with "
        "apm.yml, including Git source, ref, host provider, transport, and MCP "
        "config state, or when deployed files do not match the hashes it records "
        "(CI-safe; mutually exclusive with --update, --mcp, and positional packages). "
        "Default when CI is truthy and apm.lock.yaml exists; --no-frozen opts out."
    ),
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed installation information")
@trust_transitive_mcp_option
@click.option(
    "--parallel-downloads",
    type=int,
    default=4,
    show_default=True,
    help="Max concurrent package downloads (0 to disable parallelism)",
)
@click.option(
    "--dev",
    is_flag=True,
    default=False,
    help="Install as development dependency (devDependencies)",
)
@click.option(
    "--target",
    "-t",
    "target",
    type=TargetParamType(),
    default=None,
    help=f"Target harness(es) to deploy to. Use commas for multiple targets; repeating the flag "
    f"keeps only the last value (use commas instead). {target_help_fragment('install')} "
    "'intellij' writes JetBrains MCP config once apm.yml exists (file primitives use the "
    "Copilot profile) and is never recorded in apm.yml; record 'copilot' for JetBrains. "
    f"{target_all_exclusion_help()}. Combine explicit-only targets when needed. "
    "Experimental targets require their feature flags. "
    "Target resolution: --runtime/--target > apm.yml targets: > apm config set target ... > "
    "auto-detect (only when no higher-priority selection exists). With nothing to detect, install "
    "exits 2 with a teaching message. For 'apm compile', use '--all'; '--target all' "
    "is deprecated.",
)
@click.option(
    "--allow-insecure",
    "allow_insecure",
    is_flag=True,
    default=False,
    help="Allow HTTP (insecure) dependencies. Required when dependencies use http:// URLs.",
)
@click.option(
    "--allow-insecure-host",
    "allow_insecure_hosts",
    multiple=True,
    callback=_allow_insecure_host_callback,
    metavar="HOSTNAME",
    help="Allow transitive HTTP (insecure) dependencies from this hostname. Repeat for multiple hosts.",
)
@click.option(
    "--global",
    "-g",
    "global_",
    is_flag=True,
    default=False,
    help="Install to the APM user home ($APM_HOME, default ~/.apm) instead of the current project. Direct MCP installs create or update the user manifest. APM_HOME controls metadata but not target deployment. Mixed selections warn and skip workspace-only runtimes; selections with no global-capable runtime exit 2 before changing the user manifest, lockfile, or runtime configuration. Runtimes without user-scope support are skipped with a warning that lists the supported ones.",
)
@click.option(
    "--ssh",
    "use_ssh",
    is_flag=True,
    default=False,
    help="Prefer SSH transport for shorthand (owner/repo) dependencies. Mutually exclusive with --https.",
)
@click.option(
    "--https",
    "use_https",
    is_flag=True,
    default=False,
    help="Prefer HTTPS transport for shorthand (owner/repo) dependencies. Mutually exclusive with --ssh.",
)
@click.option(
    "--allow-protocol-fallback",
    "allow_protocol_fallback",
    is_flag=True,
    default=False,
    help="Restore the legacy permissive cross-protocol fallback chain (escape hatch for migrating users; also: APM_ALLOW_PROTOCOL_FALLBACK=1). Caveat: fallback reuses the same port across schemes; on servers that use different SSH and HTTPS ports, omit this flag and pin the dependency with an explicit ssh:// or https:// URL.",
)
@click.option(
    "--auth-first",
    "auth_first",
    is_flag=True,
    default=False,
    help="Skip the anonymous-first HTTPS attempt for github.com and use your resolved credentials immediately (also: APM_GITHUB_AUTH_FIRST=1, apm config set github-auth-first true). Escape hatch for TLS-inspecting proxies the isolated anonymous attempt cannot pass. Trade-off: forwards credentials on the first attempt.",
)
@click.option(
    "--mcp",
    "mcp_name",
    default=None,
    metavar="NAME",
    help=(
        "Add an MCP server entry to apm.yml. Use with --transport, --url, --env, "
        "--header, --mcp-version, or a stdio command after `--`. Resolves active "
        "targets as --runtime/--target > apm.yml targets: > apm config set target ... > auto-detect "
        "(only when no higher-priority selection exists); writes only for active targets."
    ),
)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http", "sse", "streamable-http"]),
    default=None,
    help="MCP transport (stdio, http, sse, streamable-http). Inferred from --url or post-- command when omitted (requires --mcp).",
)
@click.option(
    "--url",
    "url",
    default=None,
    help="MCP server URL for http/sse/streamable-http transports (requires --mcp).",
)
@click.option(
    "--env",
    "env_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help="Environment variable for stdio MCP, repeatable (requires --mcp).",
)
@click.option(
    "--header",
    "header_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help="HTTP header for remote MCP, repeatable (requires --mcp and --url).",
)
@click.option(
    "--mcp-version",
    "mcp_version",
    default=None,
    help="Pin MCP registry entry to a specific version (requires --mcp).",
)
@click.option(
    "--registry",
    "registry_url",
    default=None,
    metavar="URL",
    help=(
        "MCP registry URL (http:// or https://) for resolving --mcp NAME. "
        "Precedence: this flag, MCP_REGISTRY_URL, apm config, then the public "
        "default. Captured in apm.yml on the entry's "
        "'registry:' field for auditability. Not valid with --url "
        "or a stdio command (self-defined entries)."
    ),
)
@click.option(
    "--skill",
    "skill_names",
    multiple=True,
    metavar="NAME",
    help="Install only named skill(s) from a SKILL_BUNDLE. Repeatable. Persisted in apm.yml and apm.lock so bare 'apm install' is deterministic. Additive across installs: a later --skill X adds X to the existing pin (union) rather than replacing it. Use --skill '*' (quote the asterisk in your shell) to reset to all skills; to drop a single skill, edit the skills: list in apm.yml then re-run apm install.",
)
@click.option(
    "--no-policy",
    "no_policy",
    is_flag=True,
    default=False,
    help="Skip org policy enforcement for this invocation. Does NOT bypass apm audit --ci.",
)
@explicit_policy_option
@click.option(
    "--audit",
    "audit_mode",
    type=click.Choice(["off", "warn", "block"], case_sensitive=False),
    default=None,
    help=(
        "Run 'apm audit' over deployed files during install: off, warn, or block. "
        "Overrides config/policy. Requires 'apm experimental enable external-scanners'. "
        "An org policy 'block' cannot be relaxed below by this flag."
    ),
)
@click.option(
    "--no-audit",
    "no_audit",
    is_flag=True,
    default=False,
    help="Disable the install-time audit for this invocation (equivalent to --audit off).",
)
@click.option(
    "--refresh",
    is_flag=True,
    default=False,
    help="Re-fetch all dependencies from upstream and re-resolve all ref pins. Marketplaces are "
    "revalidated; the install fails rather than use stale marketplace data. Use 'apm update' for "
    "interactive upgrade planning.",
)
@click.option(
    "--legacy-skill-paths",
    "legacy_skill_paths",
    is_flag=True,
    default=False,
    help=(
        "Deploy skill files to per-client paths (e.g. .cursor/skills/) instead of "
        "the shared .agents/skills/ directory. Compatibility flag for projects that "
        "need per-client skill layouts."
    ),
)
@click.option(
    "--as",
    "alias",
    default=None,
    metavar="ALIAS",
    help=(
        "Override the log/display label when installing a local bundle "
        "(directory, .zip, or .tar.gz produced by 'apm pack'). Only valid for "
        "local-bundle installs; passing --as without a local bundle path is rejected."
    ),
)
@click.option(
    "--trust-bin/--no-trust-bin",
    "trust_bin",
    default=None,
    help=(
        "Allow or skip bin/ executable deployment for this invocation. "
        "--trust-bin deploys bin/ executables (suppresses the trust warning). "
        "--no-trust-bin skips bin/ deployment even when policy allows it. "
        "Default: deploys bin/ but emits a warning; non-interactive contexts "
        "skip bin/ by default. Use 'apm approve' for persistent per-package trust."
    ),
)
@click.option(
    "--root",
    "root",
    type=click.Path(file_okay=False, resolve_path=True),
    default=None,
    metavar="DIR",
    help=(
        "Install into DIR instead of $PWD: apm_modules/, apm.lock.yaml, "
        ".claude/, .codex/, .agents/, .opencode/ are written under DIR "
        "while sources (apm.yml, .apm/, local-path packages) continue "
        "resolving from $PWD. Mirrors 'pip install --target' / "
        "'npm install --prefix'. Project scope only; not valid with --global."
    ),
)
@click.pass_context
@serialized_lifecycle_unless_fresh_preview("dry_run")
def install(ctx, dry_run, **options):
    """Replay a verified no-op, else run the full install command body."""
    from apm_cli.install.noop_fast_path import run_with_fast_path

    def run_install():
        body = importlib.import_module("apm_cli.commands.install").install_command_body
        return body(ctx, dry_run=dry_run, **options)

    return run_with_fast_path({**options, "dry_run": dry_run}, run_install)
