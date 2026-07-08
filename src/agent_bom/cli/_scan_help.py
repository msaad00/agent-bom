"""Help tiering for the large ``scan`` command.

The ``scan`` command carries ~200 flags. A flat ``--help`` buries the handful
of options a first-time user needs under dozens of cloud/identity/compliance and
vendor-integration knobs. :class:`TieredCommand` partitions the option help into
three tiers without changing any option's behavior:

* **Core options** — the narrow front-door set (path, ``-f/--format``,
  ``-o/--output``, ``--fail-on-*``, ``--demo``, provider connect flags, …).
* **More options** — everything else that is not a vendor-token integration.
* **Integrations & vendor tokens** — third-party credential/endpoint flags
  (Jira, Slack, ServiceNow, Snyk tokens, Drata, Vanta, W&B, Nebius, OpenAI, HF
  tokens, Iceberg, SIEM, …). These are shown only under ``--help-all`` and their
  backing environment variable is surfaced in the record.

:class:`AliasedChoice` lets ``-f`` accept a deprecated spelling (``text``) that
maps to the canonical value (``plain``) while keeping the alias out of the
advertised choice list.
"""

from __future__ import annotations

import click

# Signals, via ctx.meta, that the user asked for the full catalog.
_HELP_ALL_KEY = "agent_bom.scan.help_all"

# The narrow front door — shown first and prominently in ``scan --help``.
CORE_FLAGS: frozenset[str] = frozenset(
    {
        "--project",
        "--repo",
        "--inventory",
        "--no-discover",
        "--output",
        "--format",
        "--demo",
        "--self-scan",
        "--offline",
        "--no-scan",
        "--enrich",
        "--transitive",
        "--introspect",
        "--enforce",
        "--preset",
        "--fail-on-severity",
        "--warn-on",
        "--fail-on-kev",
        "--fail-on-malicious",
        "--fail-if-ai-risk",
        "--save",
        "--baseline",
        "--policy",
        "--aws",
        "--azure",
        "--gcp",
        "--verbose",
        "--quiet",
        "--agent-mode",
    }
)

# Third-party credential/endpoint flags — hidden unless ``--help-all``.
VENDOR_FLAGS: frozenset[str] = frozenset(
    {
        # Jira
        "--jira-url",
        "--jira-user",
        "--jira-token",
        "--jira-project",
        # Slack
        "--slack-webhook",
        "--slack-bot-token",
        # ServiceNow
        "--servicenow-instance",
        "--servicenow-token",
        # Snyk (tokens only — the bare --snyk toggle stays visible)
        "--snyk-token",
        "--snyk-org",
        # GRC
        "--drata-token",
        "--vanta-token",
        # Weights & Biases
        "--wandb-api-key",
        "--wandb-entity",
        "--wandb-project",
        # Nebius
        "--nebius-api-key",
        "--nebius-project-id",
        # OpenAI
        "--openai-api-key",
        "--openai-org-id",
        # Hugging Face (tokens/scoping — the --hf-model scan target stays visible)
        "--hf-token",
        "--hf-username",
        "--hf-organization",
        # Iceberg lake
        "--iceberg-catalog-url",
        "--iceberg-namespace",
        "--iceberg-table",
        # SIEM
        "--siem",
        "--siem-url",
        "--siem-token",
        "--siem-index",
        "--siem-format",
        # Central dashboard push
        "--push-url",
        "--push-api-key",
        # ClickHouse analytics
        "--clickhouse-url",
    }
)

_HELP_FLAGS = frozenset({"--help", "-h", "--help-all"})


def _param_flags(param: click.Parameter) -> set[str]:
    return set(getattr(param, "opts", []) or []) | set(getattr(param, "secondary_opts", []) or [])


def _help_all_callback(ctx: click.Context, param: click.Parameter, value: bool):
    """Eager ``--help-all`` handler: render the full catalog and exit."""
    if not value or ctx.resilient_parsing:
        return
    ctx.meta[_HELP_ALL_KEY] = True
    click.echo(ctx.get_help(), color=ctx.color)
    ctx.exit()


class TieredCommand(click.Command):
    """A ``click.Command`` that tiers option help into Core / More / Vendor."""

    core_flags = CORE_FLAGS
    vendor_flags = VENDOR_FLAGS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.append(
            click.Option(
                ["--help-all"],
                is_flag=True,
                is_eager=True,
                expose_value=False,
                callback=_help_all_callback,
                help="Show every option, including advanced integration and vendor-token flags.",
            )
        )

    def _tier(self, param: click.Parameter) -> str:
        flags = _param_flags(param)
        if flags & _HELP_FLAGS:
            return "core"
        if flags & self.vendor_flags:
            return "vendor"
        if flags & self.core_flags:
            return "core"
        return "more"

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        show_all = bool(ctx.meta.get(_HELP_ALL_KEY, False))
        core: list[tuple[str, str]] = []
        more: list[tuple[str, str]] = []
        vendor: list[tuple[str, str]] = []

        for param in self.get_params(ctx):
            if isinstance(param, click.Argument):
                continue
            tier = self._tier(param)
            if tier == "vendor" and isinstance(param, click.Option) and getattr(param, "envvar", None):
                # Surface the backing env var for vendor-token flags.
                original = param.show_envvar
                param.show_envvar = True
                try:
                    record = param.get_help_record(ctx)
                finally:
                    param.show_envvar = original
            else:
                record = param.get_help_record(ctx)
            if record is None:  # hidden options (e.g. deprecated aliases)
                continue
            if tier == "core":
                core.append(record)
            elif tier == "vendor":
                vendor.append(record)
            else:
                more.append(record)

        if core:
            with formatter.section("Core options"):
                formatter.write_dl(core)
        if more:
            with formatter.section("More options"):
                formatter.write_dl(more)
        if show_all:
            if vendor:
                with formatter.section("Integrations & vendor tokens"):
                    formatter.write_dl(vendor)
        elif vendor:
            with formatter.section("Integrations & vendor tokens"):
                formatter.write_text(
                    f"{len(vendor)} third-party credential/endpoint flags (Jira, Slack, ServiceNow, "
                    "Snyk, Drata, Vanta, W&B, Nebius, OpenAI, Hugging Face, Iceberg, SIEM, …) are "
                    "hidden. Run `agent-bom scan --help-all` to see them with their env vars."
                )


class AliasedChoice(click.Choice):
    """A ``click.Choice`` that accepts deprecated aliases mapped to canonical values.

    Aliases are accepted by :meth:`convert` but excluded from the advertised
    choice list / metavar so ``--help`` shows only the canonical options.
    """

    def __init__(self, choices, aliases: dict[str, str] | None = None, case_sensitive: bool = True):
        super().__init__(list(choices), case_sensitive=case_sensitive)
        self.aliases = dict(aliases or {})

    def convert(self, value, param, ctx):
        if isinstance(value, str) and value in self.aliases:
            value = self.aliases[value]
        return super().convert(value, param, ctx)
