"""The light ``apm install`` command forwards exactly the body's parameters."""

from __future__ import annotations

import inspect

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.promise("P-OWN-cli-startup-import-budget")]


def test_install_entry_is_the_install_command_and_forwards_every_body_parameter() -> None:
    import apm_cli.commands.install as install_module
    from apm_cli.commands import install_entry

    assert install_module.install is install_entry.install
    option_names = {param.name for param in install_entry.install.params}
    # --policy is consumed by explicit_policy_option before the callback runs.
    option_names.discard("policy_source")
    body = list(inspect.signature(install_module.install_command_body).parameters)
    assert body[0] == "ctx"
    assert option_names == set(body[1:])
