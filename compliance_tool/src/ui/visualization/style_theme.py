from dataclasses import dataclass


@dataclass(frozen=True)
class Theme:
    name: str
    background: str
    text: str
    system_node: str
    system_node_edge: str
    testcase_node: str
    teststep_node: str
    link_covered: str
    link_uncovered: str
    shadow: str
    banner_bg: str
    legend_bg: str


LIGHT_THEME = Theme(
    name="Light",
    background="#f7f8fb",
    text="#1b1f24",
    system_node="#b7d7f0",
    system_node_edge="#5a7ea6",
    testcase_node="#f2b48f",
    teststep_node="#d8c7f2",
    link_covered="#5cb85c",
    link_uncovered="#d9534f",
    shadow="#000000",
    banner_bg="#e9eef6",
    legend_bg="#ffffff",
)

DARK_THEME = Theme(
    name="Dark",
    background="#1e2227",
    text="#e6e8eb",
    system_node="#557aa2",
    system_node_edge="#9db7d3",
    testcase_node="#c07a4f",
    teststep_node="#7d6aa6",
    link_covered="#7ad67a",
    link_uncovered="#f08080",
    shadow="#000000",
    banner_bg="#2b3036",
    legend_bg="#24282e",
)


def get_theme(name: str) -> Theme:
    if name and name.lower().startswith("dark"):
        return DARK_THEME
    return LIGHT_THEME
