"""The modality arm changes one paragraph of the agent prompt and nothing else."""
from pathlib import Path

import pytest

from harness.runtime.case import MODALITIES, CaseError, CaseSpec, build_prompt

SPEC = CaseSpec(seed_id="x", seed_dir=Path("."), initial_tf=(), utterance="Add a tag.",
                terraform_types=(), cloudcontrol_types=(), resolution_prompt="Keep what you found.")


def _prompt(modality: str) -> str:
    return build_prompt(SPEC, region="us-east-1", modality=modality)


def test_hybrid_is_the_default_and_names_all_three_tools():
    assert build_prompt(SPEC, region="us-east-1") == _prompt("hybrid")
    for tool in ("`aws` CLI", "boto3", "Terraform"):
        assert tool in _prompt("hybrid")


@pytest.mark.parametrize("modality,required,forbidden_phrase", [
    ("iac", "Terraform", "other than Terraform"),
    ("sdk", "boto3", "Do not use the `aws` CLI"),
    ("cli", "`aws` CLI", "Do not write Terraform"),
])
def test_pinned_modalities_prescribe_one_tool(modality, required, forbidden_phrase):
    prompt = _prompt(modality)
    assert required in prompt and forbidden_phrase in prompt


def test_only_the_modality_paragraph_differs():
    def rest(p: str) -> list[str]:
        lines = p.splitlines()
        return [l for l in lines if not (l.startswith(("Use whatever", "Manage the infrastructure", "Make every change"))
                                        or "Do not touch resources unrelated" in l)]
    # Everything except the tooling paragraph (which ends on the 'unrelated' sentence) is shared.
    baseline = rest(_prompt("hybrid"))
    for modality in MODALITIES:
        shared = rest(_prompt(modality))
        assert [l for l in shared if l.startswith(("## ", "You are operating", "Work only", "Call `finish`"))] == \
               [l for l in baseline if l.startswith(("## ", "You are operating", "Work only", "Call `finish`"))]
        assert "shared" not in _prompt(modality).lower()   # never says the environment is shared


def test_unknown_modality_is_refused():
    with pytest.raises(CaseError, match="modality"):
        _prompt("ansible")


def test_agent_terraform_providers_are_pruned(tmp_path):
    from scripts.run_case import _prune_agent_terraform

    providers = tmp_path / "infra" / ".terraform" / "providers" / "registry.terraform.io" / "hashicorp" / "aws"
    providers.mkdir(parents=True)
    (providers / "terraform-provider-aws").write_bytes(b"x" * 10)
    (tmp_path / "infra" / ".terraform.lock.hcl").write_text("provider ...")
    (tmp_path / "infra" / "terraform.tfstate").write_text("{}")
    # ...and a cache directory the agent invented for itself in the workspace.
    invented = tmp_path / ".plugin-cache" / "registry.terraform.io" / "hashicorp" / "aws" / "6.64.0"
    invented.mkdir(parents=True); (invented / "terraform-provider-aws").write_bytes(b"y" * 10)
    assert _prune_agent_terraform(tmp_path) == 2
    assert not (tmp_path / "infra" / ".terraform" / "providers" / "registry.terraform.io").exists()
    assert not (tmp_path / ".plugin-cache" / "registry.terraform.io").exists()
    assert (tmp_path / "infra" / ".terraform.lock.hcl").exists() and (tmp_path / "infra" / "terraform.tfstate").exists()


def test_agent_plugin_cache_is_seeded_from_the_harness_cache_once(tmp_path):
    from scripts.run_case import _agent_plugin_cache

    source = tmp_path / "cache"; (source / "registry.terraform.io" / "hashicorp" / "aws" / "5.100.0").mkdir(parents=True)
    (source / "registry.terraform.io" / "hashicorp" / "aws" / "5.100.0" / "provider").write_bytes(b"bin")
    (source / ".terraform-init.lock").write_text("")
    target = tmp_path / "cache-agent"
    assert _agent_plugin_cache(source, target) == target
    assert (target / "registry.terraform.io" / "hashicorp" / "aws" / "5.100.0" / "provider").read_bytes() == b"bin"
    assert not (target / ".terraform-init.lock").exists()
    # A later, newer provider in the source is not copied again: the agent cache is its own.
    (source / "registry.terraform.io" / "hashicorp" / "aws" / "6.0.0").mkdir()
    _agent_plugin_cache(source, target)
    assert not (target / "registry.terraform.io" / "hashicorp" / "aws" / "6.0.0").exists()


def test_agent_terraformrc_pins_the_agent_cache(tmp_path):
    from scripts.run_case import _agent_terraformrc

    cache = tmp_path / "terraform-plugin-cache-agent"; cache.mkdir()
    rc = _agent_terraformrc(cache)
    assert rc.parent == tmp_path and f'plugin_cache_dir = "{cache}"' in rc.read_text()
    assert _agent_terraformrc(cache) == rc   # idempotent


def test_policy_flag_leaves_the_policy_out_and_nothing_else():
    shown = build_prompt(SPEC, region="us-east-1")
    hidden = build_prompt(SPEC, region="us-east-1", policy=False)
    assert "Keep what you found." in shown and "## Policy" in shown
    assert "Keep what you found." not in hidden and "## Policy" not in hidden
    assert hidden == shown.replace("\n## Policy\nKeep what you found.\n", "")
