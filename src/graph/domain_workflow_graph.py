"""Inner HENNGE workflow graph (Cat 2 domain workflow).

Instantiated by HenngeWorkflowGraphNode.get_subgraph() in graph.py. Inherits
BaseGraph directly for a fully custom linear topology:

    START -> validate_input -> classify_intent -> infer_hennge_fields
          -> call_hennge_api -> confirm -> END

Config (forwarded from the outer graph via _parent_config(), under
config["configurable"]):
    hennge   - the integration settings from config/config.yaml (base_url,
               timeout_s); injected into State as the JSON `hennge_config`
               field via _extra_initial_state() so the no-arg nodes can read it

Nodes are registered WITHOUT constructor arguments (SDK v1 nodes are no-arg;
ctor args raise TypeError at graph build).
"""

from typing import Any

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_status import AgentStatus
from src.nodes.validate_input_node import ValidateInputNode
from src.nodes.classify_intent_node import ClassifyIntentNode
from src.nodes.infer_hennge_fields_node import InferHenngeFieldsNode
from src.nodes.call_hennge_api_node import CallHenngeApiNode
from src.nodes.confirm_node import ConfirmNode
from src.schemas.state import State, to_json


class HenngeWorkflowGraph(BaseGraph):
    """Inner graph: NL -> validate -> classify -> infer -> call -> confirm."""

    @property
    def name(self) -> str:
        return "hennge_access_control_workflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        # No mandatory config: the hennge section is optional (the client
        # falls back to the documented default base_url + the network-free
        # stub transport), and a missing/unusable setting is handled at
        # CallHenngeApiNode.execute() as a graceful status=error rather than
        # a compile-time crash.
        pass

    def register_nodes(self) -> None:
        # No super() - BaseGraph.register_nodes() is abstract. Do NOT register
        # initialize / finalize (outer backbone concern). All nodes are no-arg.
        self._nodes["validate_input"] = ValidateInputNode()
        self._nodes["classify_intent"] = ClassifyIntentNode()
        self._nodes["infer_hennge_fields"] = InferHenngeFieldsNode()
        self._nodes["call_hennge_api"] = CallHenngeApiNode()
        self._nodes["confirm"] = ConfirmNode()

    def add_edges(self) -> None:
        self._sg.add_edge(START, "validate_input")
        self._sg.add_edge("validate_input", "classify_intent")
        self._sg.add_edge("classify_intent", "infer_hennge_fields")
        self._sg.add_edge("infer_hennge_fields", "call_hennge_api")
        self._sg.add_edge("call_hennge_api", "confirm")
        self._sg.add_edge("confirm", END)

    def route(self, state: State) -> str:
        # Required by BaseGraph ABC. Linear topology -> not referenced by any
        # add_conditional_edges() today. The annotation is this graph's OWN
        # State on purpose: LangGraph reads a path callable's annotation as its
        # input schema and projects away every field the annotation does not
        # declare, so annotating a base state here would make the domain fields
        # this predicate reads permanently absent the moment the callable is
        # wired to a conditional edge.
        return END if state.get("status") == AgentStatus.ERROR.value else "confirm"

    def _extra_initial_state(self) -> dict[str, Any]:
        # Forward the `hennge` integration settings (arriving under
        # config["configurable"] from _parent_config()) into State as a JSON
        # string (checkpoint-serialization contract) so the no-arg
        # CallHenngeApiNode can read it via state.get("hennge_config").
        configurable = self.config.get("configurable") or {}
        hennge = configurable.get("hennge") or {}
        if not hennge:
            return {}
        return {"hennge_config": to_json(hennge)}

    def get_output(self, state: State) -> dict[str, Any]:
        return {
            "output": state.get("result") or state.get("confirmation"),
            "status": state.get("status"),
            "intent": state.get("intent", ""),
            "user_id": state.get("user_id", ""),
            "record_id": state.get("record_id", ""),
            "record_ref": state.get("record_ref", ""),
            "app_name": state.get("app_name", ""),
            "confirmation": state.get("confirmation", ""),
            "hennge_payload": state.get("hennge_payload", ""),
            "redaction_flags": state.get("redaction_flags", ""),
            "error_log": state.get("error_log", []),
            "trace_id": state.get("trace_id", ""),
            "correlation_id": state.get("correlation_id", ""),
            "node_history": state.get("node_history", []),
        }
