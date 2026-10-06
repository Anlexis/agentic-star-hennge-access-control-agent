"""CMN-C2-282 outer graph (Cat 2).

Cat 2: fixed 5-node backbone (initialize -> pre_process -> main -> post_process ->
finalize). Domain complexity is encapsulated in HenngeWorkflowGraphNode (`main`
slot), which wraps the inner HenngeWorkflowGraph (validate -> classify -> infer ->
call -> confirm). add_edges() is NOT overridden - backbone wiring is the
framework's concern.

Runtime settings live in `config/config.yaml` (the static manifest
`config/agent.yaml` carries identity and compile-time requirements only). The
entry point passes that file's contents to the graph constructor, and
HenngeWorkflowGraphNode._parent_config() forwards the integration section to the
inner graph.
"""

from pathlib import Path
from typing import Any, ClassVar

import yaml

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import State

# Runtime config: src/graph/graph.py -> parents[2] = repo root.
_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

# Runtime keys that belong to the HENNGE integration and are forwarded to the
# inner graph when they are declared at the root of config/config.yaml.
_FORWARDED_RUNTIME_KEYS = ("timeout_s",)


def load_runtime_config() -> dict[str, Any]:
    """Return the parsed `config/config.yaml`, or `{}` when it is unreadable.

    This is the ONLY runtime-settings source. `config/agent.yaml` is the static
    manifest and carries no runtime block, so reading it here would return
    nothing and every declared setting would silently fall back to a default.
    """
    try:
        loaded = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


class HenngeWorkflowGraphNode(GraphNode):
    """Wraps the inner HENNGE workflow graph; assigned to the `main` slot.

    No constructor arguments (SDK v1 nodes are no-arg) - configuration reaches
    the subgraph via _parent_config(), which loads the runtime config file.
    """

    # Fail fast: re-raise inner-graph exceptions as SubgraphError (default).
    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> Any:
        from src.graph.domain_workflow_graph import HenngeWorkflowGraph

        return HenngeWorkflowGraph(config=self._parent_config())

    def extract_input(self, state: AgentState) -> str:
        # pre_process serialized the request into validated_input (JSON string);
        # structured params travel as JSON and the first inner node parses them back.
        # This envelope is how caller-supplied context reaches the inner graph:
        # GraphNode.execute() calls subgraph.invoke() WITHOUT input_context, so a
        # value read straight from state["input_context"] inside the subgraph would
        # always be absent.
        return str(state.get("validated_input") or state.get("user_input", ""))

    def merge_output(self, state: AgentState, sub_result: dict[str, Any]) -> dict[str, Any]:
        # Map only the keys this node changes back into the outer state.
        return {
            "result": sub_result.get("output"),
            "status": sub_result.get("status"),
            "intent": sub_result.get("intent", ""),
            "user_id": sub_result.get("user_id", ""),
            "record_id": sub_result.get("record_id", ""),
            "record_ref": sub_result.get("record_ref", ""),
            "app_name": sub_result.get("app_name", ""),
            "confirmation": sub_result.get("confirmation", ""),
            "hennge_payload": sub_result.get("hennge_payload", ""),
            "redaction_flags": sub_result.get("redaction_flags", ""),
            "error_log": sub_result.get("error_log", []),
        }

    def _parent_config(self) -> dict[str, Any]:
        """Forward the runtime integration settings under config["configurable"].

        Reads `config/config.yaml` and forwards its `hennge:` section, enriched
        with the root-level runtime keys the integration consumes (`timeout_s`)
        - never an empty {}, which would make every declared setting dead.
        """
        runtime = load_runtime_config()
        integration = dict(runtime.get("hennge") or {})
        for key in _FORWARDED_RUNTIME_KEYS:
            if key in runtime and key not in integration:
                integration[key] = runtime[key]
        return {"configurable": {"hennge": integration}}


class HENNGEAccessControlAgent(AgentBaseGraph):
    """CMN-C2-282 outer graph - HENNGE Access Control Agent.

    Backbone: initialize -> pre_process -> main -> post_process -> finalize (fixed).
    Domain logic lives in HenngeWorkflowGraphNode (`main` slot); HENNGE
    settings flow from config/config.yaml via _parent_config().
    """

    @property
    def name(self) -> str:
        return "cmn_c2_282"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = HenngeWorkflowGraphNode()
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden - backbone wiring belongs to the framework.
