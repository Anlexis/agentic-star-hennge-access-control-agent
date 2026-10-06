# CMN-C2-282 - Unit tests: inner HenngeWorkflowGraph (BaseGraph) contract.
# The compiled outer path is
# exercised end-to-end by tests/proof_of_boundary/test_pb_invoke_order.py; this
# module unit-checks the inner graph's identity, config forwarding, routing,
# output contract, and a direct inner invoke on the network-free stub.

from langgraph.graph import END

from framework.schemas.agent_status import AgentStatus

from src.graph.domain_workflow_graph import HenngeWorkflowGraph
from src.schemas.state import State, from_json


def _graph(config=None):
    return HenngeWorkflowGraph(config=config or {})


def test_inner_graph_identity():
    g = _graph()
    assert g.name == "hennge_access_control_workflow"
    assert g.state_schema is State


def test_extra_initial_state_injects_hennge_config_as_json():
    g = _graph({"configurable": {"hennge": {"base_url": "https://hennge.example.test/v1"}}})
    extra = g._extra_initial_state()
    # Forwarded as a JSON string, not a native dict.
    assert isinstance(extra["hennge_config"], str)
    assert from_json(extra["hennge_config"], {}) == {"base_url": "https://hennge.example.test/v1"}


def test_extra_initial_state_empty_without_hennge_section():
    assert _graph()._extra_initial_state() == {}


def test_route_error_ends_graph():
    g = _graph()
    assert g.route({"status": AgentStatus.ERROR.value}) == END
    assert g.route({"status": AgentStatus.SUCCESS.value}) == "confirm"


def test_get_output_surfaces_record_fields():
    g = _graph()
    out = g.get_output(
        {
            "result": {"record_id": "u-1001", "record_ref": "hennge://users/u-1001/applications", "confirmation": "ok"},
            "status": AgentStatus.SUCCESS.value,
            "intent": "lookup_access",
            "user_id": "u-1001",
            "record_id": "u-1001",
            "record_ref": "hennge://users/u-1001/applications",
            "app_name": "Salesforce",
            "confirmation": "ok",
            "hennge_payload": "{}",
            "redaction_flags": "[]",
            "error_log": [],
            "trace_id": "tr",
            "correlation_id": "co",
            "node_history": ["ValidateInputNode", "ConfirmNode"],
        }
    )
    assert out["status"] == AgentStatus.SUCCESS.value
    assert out["intent"] == "lookup_access"
    assert out["record_ref"] == "hennge://users/u-1001/applications"
    assert out["confirmation"] == "ok"
    assert out["output"] == {
        "record_id": "u-1001",
        "record_ref": "hennge://users/u-1001/applications",
        "confirmation": "ok",
    }


def test_get_output_carries_error_log():
    g = _graph()
    out = g.get_output({"status": AgentStatus.ERROR.value, "error_log": ["boom"], "confirmation": ""})
    assert out["status"] == AgentStatus.ERROR.value
    assert out["error_log"] == ["boom"]


def test_inner_graph_compiles():
    g = _graph()
    g.compile()
    assert g._compiled is not None


def test_inner_invoke_lookup_on_v1_stub():
    """Direct inner invoke (default ANONYMOUS ctx - every inner node is
    ANONYMOUS): validate -> classify -> infer -> call(stub) -> confirm."""
    g = _graph({"configurable": {"hennge": {"base_url": "https://api.hennge.one/v1"}}})
    g.compile()
    result = g.invoke(
        user_input="Look up the app access status for user id u-1001 and summarize the current assignments on file."
    )
    assert result["status"] == AgentStatus.SUCCESS.value
    assert result["record_id"] == "u-1001"
    assert result["record_ref"] == "hennge://users/u-1001/applications"
    assert result["intent"] == "lookup_access"
    assert result["confirmation"]
    history = result.get("node_history", [])
    assert history == [
        "ValidateInputNode",
        "ClassifyIntentNode",
        "InferHenngeFieldsNode",
        "CallHenngeApiNode",
        "ConfirmNode",
    ]
