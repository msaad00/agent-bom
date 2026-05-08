# Contributing Skills

Start with the root skill contribution guide:

- [Contributing agent-bom skills](../CONTRIBUTING_SKILLS.md)
- [Skill capability contract](CAPABILITIES.md)

Before opening a skill PR, check that the skill has:

- explicit source, homepage, license, install, runtime dependency, credential,
  network, persistence, and telemetry metadata
- a complete `capabilities` or `skill_capabilities` map
- a first command, expected artifact, and schema or validation path
- no raw credential output, hidden write behavior, or unbounded shell/network
  behavior
- verification evidence from the relevant CLI, API, MCP, runtime, or docs path

Do not present a skill as Snowflake Native App, MCP runtime, or sandbox ready
until the capability map, credential boundary, artifact schema, and smoke
evidence are all documented.
