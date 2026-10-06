# Unit tests: the agent manifest and the runtime config it is split from.
#
# config/agent.yaml is the FLAT registry manifest: identity, entry point and
# compile-time requirements, all at root level. config/config.yaml holds the
# runtime settings. The split matters for more than tidiness - a reader that
# still looks for runtime values inside the manifest gets nothing back and the
# declared values go dead, so these tests pin both files AND the reader.

import pathlib

import pytest

try:
    import yaml  # pyyaml (transitive dep of the framework wheel)

    _YAML_ERROR = None
except Exception as exc:  # pragma: no cover
    yaml = None
    _YAML_ERROR = exc

_ROOT = pathlib.Path(__file__).parents[2]
_MANIFEST_PATH = _ROOT / "config" / "agent.yaml"
_RUNTIME_PATH = _ROOT / "config" / "config.yaml"

pytestmark = pytest.mark.skipif(_YAML_ERROR is not None, reason=f"pyyaml unavailable: {_YAML_ERROR}")


def _manifest():
    return yaml.safe_load(_MANIFEST_PATH.read_text())


def _runtime():
    return yaml.safe_load(_RUNTIME_PATH.read_text())


def test_manifest_identity():
    data = _manifest()
    assert data["id"] == "CMN-C2-282"
    assert data["category"] == "Cat 2"
    assert data["industry"] == "CMN"
    assert data["base_type"] == "ToolCallingAgent"


def test_manifest_is_flat():
    """Every key sits at root level - a nested `agent:` block is the retired shape."""
    data = _manifest()
    assert "agent" not in data
    assert "config" not in data


def test_manifest_entry_point():
    """A single dotted import path, not a split module/class pair."""
    assert _manifest()["class"] == "src.graph.graph.HENNGEAccessControlAgent"


def test_manifest_security():
    data = _manifest()
    # Agent-level entry trust, enforced by the outer backbone pre_process gate
    # (VERIFIED_EXTERNAL); inner domain nodes stay ANONYMOUS.
    assert data["required_trust_level"] == "VERIFIED_EXTERNAL"


def test_manifest_declares_the_llm_secrets_not_the_hennge_token():
    """The HENNGE integration token is read with .get() - NOT a compile-time requirement
    (the default transport is network-free and never sends a request, so declaring it
    would make the agent refuse to compile wherever it is not provisioned for a
    credential the shipped configuration does not actually need).

    The three Azure OpenAI values ARE declared: ClassifyIntentNode / InferHenngeFieldsNode
    resolve them via ctx.secrets.require(...) when building a real client (model-backed
    synthesis, see docs/02_design.md "Implementation Note"). Their absence degrades the
    LLM call to the existing keyword/regex heuristic at runtime (never a hard node error),
    but `requires.secrets` is what the registry's require_at_compile() gate reads.
    """
    assert _manifest()["requires"]["secrets"] == [
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
    ]
    assert _manifest()["requires"]["extras"] == ["openai"]


def test_manifest_generation_mode_matches_the_code():
    """Model-backed synthesis is wired (ClassifyIntentNode/InferHenngeFieldsNode call an
    LLM), so generation_mode must say "llm" - the keyword/regex path is now the fallback,
    not the only path.
    """
    assert _manifest()["generation_mode"] == "llm"


def test_runtime_config_shape():
    runtime = _runtime()
    assert isinstance(runtime["max_retry"], int)
    assert isinstance(runtime["timeout_s"], (int, float))
    assert runtime["hennge"]["base_url"] == "https://api.hennge.one/v1"


def test_runtime_config_is_what_the_forwarder_reads():
    """The integration settings the inner graph receives come from config/config.yaml."""
    from src.graph.graph import HenngeWorkflowGraphNode

    forwarded = HenngeWorkflowGraphNode()._parent_config()["configurable"]["hennge"]
    assert forwarded["base_url"] == _runtime()["hennge"]["base_url"]
    # The root-level call budget travels with the integration settings, because
    # that is where its consumer reads it.
    assert forwarded["timeout_s"] == _runtime()["timeout_s"]
