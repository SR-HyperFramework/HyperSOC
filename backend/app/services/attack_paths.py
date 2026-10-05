"""Bounded access-path hypotheses grounded in explicitly imported relationships."""
from app.schemas.hub import HubGraph

_ACCESS_RELATIONS = {"administers", "can_access", "member_of", "trusted_by"}


def access_paths(graph: HubGraph, seeds: list, technique_predictions: list) -> dict:
    nodes = {node.id: node for node in graph.nodes}
    adjacency = {}
    for edge in graph.edges:
        if edge.relation in _ACCESS_RELATIONS and edge.confidence > 0:
            adjacency.setdefault(edge.source_id, []).append(edge)
    candidates = []
    for seed in seeds:
        frontier = [(seed.id, [], {seed.id}, 1.0)]
        while frontier and len(candidates) < 20:
            current, path, visited, confidence = frontier.pop(0)
            if len(path) >= 3:
                continue
            for edge in adjacency.get(current, []):
                destination = nodes.get(edge.target_id)
                if destination is None or destination.id in visited:
                    continue
                next_path = [*path, edge]
                next_confidence = confidence * edge.confidence
                if destination.kind == "asset" and destination.id != seed.id:
                    candidates.append({
                        "kind": "hypothesis", "entry_entity_id": str(seed.id), "target_entity_id": str(destination.id),
                        "target_label": destination.label, "target_criticality": destination.attributes.get("criticality", "unknown"),
                        "relationship_confidence": round(next_confidence, 4),
                        "steps": [{"from": str(item.source_id), "to": str(item.target_id), "relation": item.relation,
                            "source_ref": item.source_ref, "observed_at": item.observed_at.isoformat()} for item in next_path],
                        "learned_next_techniques": technique_predictions[:3],
                    })
                if len(candidates) >= 20:
                    break
                frontier.append((destination.id, next_path, visited | {destination.id}, next_confidence))
    return {
        "status": "hypotheses_available" if candidates else "insufficient_access_context",
        "assumption": "If an incident-linked identity or asset is compromised, its observed access may expose these assets.",
        "paths": candidates, "truncated": graph.truncated or len(candidates) >= 20,
        "gaps": [] if candidates else ["No explicit access relationship connects incident entities to another asset."],
    }
