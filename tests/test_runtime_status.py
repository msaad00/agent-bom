from io import StringIO

from agent_bom.cli._runtime_status import emit_runtime_status_strip, render_runtime_status_strip


class TtyStringIO(StringIO):
    def isatty(self) -> bool:
        return True


def test_render_runtime_status_strip_is_compact():
    line = render_runtime_status_strip(
        "proxy",
        calls=12,
        blocked=3,
        last_decision="blocked:scanner:credential_leak",
    )

    assert line == "  agent-bom proxy live | calls=12 blocked=3 last=blocked:scanner:credential_leak | Ctrl+C to stop"


def test_render_runtime_status_strip_truncates_multiline_decision():
    line = render_runtime_status_strip(
        "gateway",
        calls=0,
        blocked=0,
        last_decision="blocked:very-long-decision\n" + ("x" * 100),
    )

    assert "\n" not in line
    assert "last=blocked:very-long-decision " in line
    assert line.endswith("... | Ctrl+C to stop")


def test_emit_runtime_status_strip_is_tty_only():
    tty = TtyStringIO()
    plain = StringIO()

    assert emit_runtime_status_strip("gateway", stream=tty, last_decision="listening") is True
    assert "agent-bom gateway live" in tty.getvalue()

    assert emit_runtime_status_strip("gateway", stream=plain, last_decision="listening") is False
    assert plain.getvalue() == ""
