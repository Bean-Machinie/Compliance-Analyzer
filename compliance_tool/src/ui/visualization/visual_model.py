from dataclasses import dataclass
from typing import Dict


@dataclass
class SankeyNode:
    node_id: str
    label: str
    node_type: str
    metadata: dict


@dataclass
class SankeyLink:
    source: str
    target: str
    value: int
    color: str


def resolve_link_color(color_key: str, palette: Dict[str, str]) -> str:
    return palette.get(color_key, color_key)
