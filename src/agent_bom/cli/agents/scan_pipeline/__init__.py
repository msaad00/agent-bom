"""Staged pipeline behind the ``scan`` command.

Stages run in order from :mod:`.runner`: options, preflight, discovery,
inventory, matching, enrichment, report, graph, AI assets, policy, output and
gates. Each stage reads a typed :class:`.options.ScanOptions` and hands its
results forward on a :class:`.state.ScanState`.
"""
