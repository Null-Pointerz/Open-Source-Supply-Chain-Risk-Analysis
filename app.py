"""
Open Source Supply Chains: The Ripple Effect
============================================

A risk-analysis prototype that models how a compromise in ONE open-source
dependency ripples through an entire software ecosystem.

WHY THIS EXISTS
---------------
Traditional scanners score packages in isolation ("this package has a CVSS 9.8").
That ignores STRUCTURE: a CVSS 9.8 in a leaf package nobody depends on is less
dangerous than a quiet, boring utility that 90% of the ecosystem sits on top of.

This tool therefore produces TWO lists:
  1. Active Risk        -> known vulnerability, ranked by (cvss x blast radius)
  2. Structural Watchlist -> NO known vulnerability, but huge blast radius

It also traces PROPAGATION PATHS -- not just who is affected, but the exact
dependency chain a compromise travels through to reach them.

The Structural Watchlist is the core differentiator. The xz-utils backdoor
(CVE-2024-3094) had NO known CVE before discovery, so a CVSS-only scanner would
have reported it as perfectly clean. A structural/blast-radius view would have
flagged it as a catastrophic single point of failure *in advance*.

Run with:
    streamlit run app.py

Tech stack: Python 3 + NetworkX (graph) + Streamlit (UI) + pyvis (graph viz).
No database, no API calls -- the sample dataset is hardcoded below.
"""

import random
import tempfile
from collections import deque

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

# ---------------------------------------------------------------------------
# CONFIGURATION CONSTANTS
# ---------------------------------------------------------------------------

STRUCTURAL_WATCHLIST_THRESHOLD = 0.2

COLOR_ACTIVE_RISK = "#e74c3c"
COLOR_WATCHLIST = "#f1c40f"
COLOR_SAFE = "#2ecc71"
COLOR_SELECTED_BORDER = "#8e44ad"
COLOR_PATH_EDGE = "#e67e22"   # orange -> highlighted propagation path
COLOR_NORMAL_EDGE = "#b2bec3"

# ---------------------------------------------------------------------------
# 1. SAMPLE DATASET (hardcoded, in-memory -- no database)
# ---------------------------------------------------------------------------

DEPENDENCY_EDGES = [
    ("web-app", "auth-service"),
    ("web-app", "api-gateway"),
    ("web-app", "ui-components"),
    ("web-app", "analytics-sdk"),
    ("mobile-app", "auth-service"),
    ("mobile-app", "ui-components"),
    ("mobile-app", "push-notifier"),
    ("payment-service", "auth-service"),
    ("payment-service", "api-gateway"),
    ("payment-service", "audit-logger"),
    ("admin-dashboard", "api-gateway"),
    ("admin-dashboard", "ui-components"),
    ("admin-dashboard", "chart-renderer"),
    ("internal-cli", "config-loader"),
    ("internal-cli", "audit-logger"),
    ("data-pipeline", "analytics-sdk"),
    ("data-pipeline", "config-loader"),
    ("auth-service", "crypto-lib"),
    ("auth-service", "http-client"),
    ("auth-service", "json-parser"),
    ("api-gateway", "http-client"),
    ("api-gateway", "json-parser"),
    ("api-gateway", "rate-limiter"),
    ("ui-components", "template-engine"),
    ("ui-components", "date-utils"),
    ("analytics-sdk", "http-client"),
    ("analytics-sdk", "json-parser"),
    ("push-notifier", "http-client"),
    ("push-notifier", "crypto-lib"),
    ("audit-logger", "logging-core"),
    ("audit-logger", "date-utils"),
    ("chart-renderer", "date-utils"),
    ("chart-renderer", "compression-lib"),
    ("config-loader", "yaml-reader"),
    ("config-loader", "json-parser"),
    ("rate-limiter", "logging-core"),
    ("template-engine", "string-utils"),
    ("yaml-reader", "string-utils"),
    ("crypto-lib", "core-utils"),
    ("http-client", "core-utils"),
    ("http-client", "compression-lib"),
    ("json-parser", "core-utils"),
    ("json-parser", "string-utils"),
    ("logging-core", "core-utils"),
    ("date-utils", "core-utils"),
    ("string-utils", "core-utils"),
    ("compression-lib", "core-utils"),
]

KNOWN_VULNERABILITIES = {
    "http-client": {"cvss": 9.1, "cve": "CVE-2024-0001", "summary": "Request smuggling in redirect handling"},
    "template-engine": {"cvss": 7.5, "cve": "CVE-2024-0002", "summary": "Server-side template injection"},
    "yaml-reader": {"cvss": 8.8, "cve": "CVE-2024-0003", "summary": "Unsafe deserialization of tagged objects"},
    "chart-renderer": {"cvss": 6.1, "cve": "CVE-2024-0004", "summary": "Stored XSS in SVG label rendering"},
    "analytics-sdk": {"cvss": 5.3, "cve": "CVE-2024-0005", "summary": "Sensitive data written to debug logs"},
}

PACKAGE_LAYERS = {
    "web-app": "application", "mobile-app": "application", "payment-service": "application",
    "admin-dashboard": "application", "internal-cli": "application", "data-pipeline": "application",
    "auth-service": "mid", "api-gateway": "mid", "ui-components": "mid", "analytics-sdk": "mid",
    "push-notifier": "mid", "audit-logger": "mid", "chart-renderer": "mid", "config-loader": "mid",
    "rate-limiter": "mid", "template-engine": "mid", "yaml-reader": "mid",
    "crypto-lib": "foundational", "http-client": "foundational", "json-parser": "foundational",
    "logging-core": "foundational", "date-utils": "foundational", "string-utils": "foundational",
    "compression-lib": "foundational", "core-utils": "foundational",
}


def build_dependency_graph():
    """Build the directed dependency graph. Edge A -> B means "A depends on B"."""
    graph = nx.DiGraph()
    graph.add_edges_from(DEPENDENCY_EDGES)

    for package in graph.nodes:
        vuln = KNOWN_VULNERABILITIES.get(package)
        graph.nodes[package]["cvss"] = vuln["cvss"] if vuln else None
        graph.nodes[package]["cve"] = vuln["cve"] if vuln else None
        graph.nodes[package]["summary"] = vuln["summary"] if vuln else None
        graph.nodes[package]["layer"] = PACKAGE_LAYERS.get(package, "unknown")

    assert nx.is_directed_acyclic_graph(graph), "Dependency graph must be a DAG"
    return graph


# ---------------------------------------------------------------------------
# 2. CORE SCORING ALGORITHMS
# ---------------------------------------------------------------------------

def get_downstream_packages(graph, package):
    """Everyone affected if `package` is compromised = its ancestors."""
    return nx.ancestors(graph, package)


def compute_impact_score(graph, package):
    """impact_score = affected packages / (total packages - 1)."""
    total_packages = graph.number_of_nodes()
    if total_packages <= 1:
        return 0.0
    return len(get_downstream_packages(graph, package)) / (total_packages - 1)


def compute_risk_score(cvss_score, impact_score):
    """risk_score = cvss * impact, ONLY for packages with a known vuln.
    None (not 0.0) for packages with no advisory -- "no data" != "safe"."""
    if cvss_score is None:
        return None
    return cvss_score * impact_score


def analyze_ecosystem(graph):
    """Score every package once; return a dict keyed by package name."""
    analysis = {}
    for package in graph.nodes:
        downstream = get_downstream_packages(graph, package)
        impact = compute_impact_score(graph, package)
        cvss = graph.nodes[package]["cvss"]

        analysis[package] = {
            "package": package,
            "layer": graph.nodes[package]["layer"],
            "cvss": cvss,
            "cve": graph.nodes[package]["cve"],
            "summary": graph.nodes[package]["summary"],
            "impact_score": impact,
            "risk_score": compute_risk_score(cvss, impact),
            "affected_count": len(downstream),
            "direct_dependent_count": graph.in_degree(package),
            "direct_dependents": sorted(graph.predecessors(package)),
            "affected_packages": sorted(downstream),
            "dependency_count": graph.out_degree(package),
        }
    return analysis


# ---------------------------------------------------------------------------
# 3. THE TWO OUTPUT LISTS
# ---------------------------------------------------------------------------

def get_active_risk_list(analysis):
    rows = [r for r in analysis.values() if r["risk_score"] is not None]
    return sorted(rows, key=lambda r: r["risk_score"], reverse=True)


def get_structural_watchlist(analysis, threshold=STRUCTURAL_WATCHLIST_THRESHOLD):
    """No known vuln, but big blast radius. THE core differentiator: this is
    the list that would have caught xz-utils before the backdoor was found."""
    rows = [
        r for r in analysis.values()
        if r["risk_score"] is None and r["impact_score"] > threshold
    ]
    return sorted(rows, key=lambda r: r["impact_score"], reverse=True)


# ---------------------------------------------------------------------------
# 4. PROPAGATION PATHS (NEW)
# ---------------------------------------------------------------------------

def get_propagation_paths(graph, compromised_package):
    """For every package eventually affected, the exact dependency chain the
    compromise travels through to reach it.

    Computed on the reversed graph: shortest_path walks FROM the compromised
    package OUTWARD toward each dependent, one hop at a time. This is a
    deterministic graph fact (the shortest route), independent of the
    probabilistic simulation below.

    Returns: {affected_package: [compromised_package, ..., affected_package]}
    """
    reversed_graph = graph.reverse(copy=False)
    paths = {}
    for target in nx.descendants(reversed_graph, compromised_package):
        paths[target] = nx.shortest_path(reversed_graph, compromised_package, target)
    return paths


# ---------------------------------------------------------------------------
# 5. MONTE CARLO PROPAGATION SIMULATION
# ---------------------------------------------------------------------------

def simulate_single_propagation(graph, compromised_package, transmission_probability):
    """Run ONE probabilistic propagation.

    Returns:
        infected    : set of all infected packages (includes patient zero)
        infected_via: dict mapping child -> parent that infected it in THIS
                      run -- i.e. the actual traversal tree for this run,
                      usable to visualize one concrete "how it happened" story.
    """
    infected = {compromised_package}
    infected_via = {}
    queue = deque([compromised_package])

    while queue:
        current = queue.popleft()
        for dependent in graph.predecessors(current):
            if dependent in infected:
                continue
            if random.random() < transmission_probability:
                infected.add(dependent)
                infected_via[dependent] = current
                queue.append(dependent)

    return infected, infected_via


def run_monte_carlo(graph, compromised_package, transmission_probability, runs):
    """Repeat the probabilistic simulation `runs` times and summarize it."""
    total_packages = graph.number_of_nodes()
    other_packages = max(total_packages - 1, 1)

    deterministic_affected = len(get_downstream_packages(graph, compromised_package))

    per_run_affected = []
    last_infected_via = {}
    for _ in range(runs):
        infected, infected_via = simulate_single_propagation(
            graph, compromised_package, transmission_probability
        )
        per_run_affected.append(len(infected) - 1)
        last_infected_via = infected_via  # keep the final run's tree for display

    average_affected = sum(per_run_affected) / len(per_run_affected)

    return {
        "deterministic_affected": deterministic_affected,
        "deterministic_percent": 100.0 * deterministic_affected / other_packages,
        "average_affected": average_affected,
        "average_percent": 100.0 * average_affected / other_packages,
        "min_affected": min(per_run_affected),
        "max_affected": max(per_run_affected),
        "runs": runs,
        "per_run_affected": per_run_affected,
        "percent_distribution": [100.0 * c / other_packages for c in per_run_affected],
        "sample_infection_tree": last_infected_via,
    }


def build_histogram_table(per_run_affected, bucket_size=2):
    counts = {}
    for affected in per_run_affected:
        bucket_start = (affected // bucket_size) * bucket_size
        label = f"{bucket_start}-{bucket_start + bucket_size - 1}"
        counts[(bucket_start, label)] = counts.get((bucket_start, label), 0) + 1

    ordered = sorted(counts.items(), key=lambda item: item[0][0])
    return pd.DataFrame(
        {"simulation runs": [count for _, count in ordered]},
        index=[label for (_, label), _ in ordered],
    )


def path_to_edge_set(path):
    """Convert a node path [A, B, C] into the SET of graph edges it uses.

    Our graph edges point dependent -> dependency (A depends on B is edge
    A->B). nx.shortest_path on the reversed graph returns the path in
    "compromise flows outward" order [compromised, ..., affected], so the
    corresponding original-graph edges run in the OPPOSITE order.
    """
    return set(zip(path[1:], path[:-1]))


# ---------------------------------------------------------------------------
# 6. MITIGATION PRIORITY RANKING
# ---------------------------------------------------------------------------

def rank_mitigations(active_risk_rows):
    total_risk = sum(r["risk_score"] for r in active_risk_rows)
    if total_risk == 0:
        return []

    ranked = []
    for row in active_risk_rows:
        ranked.append({
            "package": row["package"],
            "risk_score": row["risk_score"],
            "risk_removed_percent": 100.0 * row["risk_score"] / total_risk,
            "affected_count": row["affected_count"],
            "cve": row["cve"],
            "cvss": row["cvss"],
        })

    return sorted(ranked, key=lambda r: r["risk_removed_percent"], reverse=True)


# ---------------------------------------------------------------------------
# 7. GRAPH VISUALIZATION (pyvis)
# ---------------------------------------------------------------------------

def classify_package(record, watchlist_names):
    if record["risk_score"] is not None:
        return "active_risk"
    if record["package"] in watchlist_names:
        return "watchlist"
    return "safe"


def build_pyvis_html(graph, analysis, watchlist_names, selected_package, highlight_edges=None):
    """Render the dependency graph to standalone HTML using pyvis.

    Color code: red = active risk, yellow = watchlist, green = safe.
    Selected compromise point gets a purple ring + star shape.
    If highlight_edges is given, those edges are drawn thick and orange --
    this is what actually shows a propagation PATH, not just an end state.
    """
    highlight_edges = highlight_edges or set()
    net = Network(height="600px", width="100%", directed=True, bgcolor="#ffffff")
    net.barnes_hut(gravity=-12000, central_gravity=0.3, spring_length=140)

    for package, record in analysis.items():
        category = classify_package(record, watchlist_names)
        color = {
            "active_risk": COLOR_ACTIVE_RISK,
            "watchlist": COLOR_WATCHLIST,
            "safe": COLOR_SAFE,
        }[category]

        cvss_text = f"{record['cvss']} ({record['cve']})" if record["cvss"] else "none known"
        tooltip = (
            f"{package}\n"
            f"layer: {record['layer']}\n"
            f"CVSS: {cvss_text}\n"
            f"impact score: {record['impact_score']:.2f}\n"
            f"packages affected if compromised: {record['affected_count']}\n"
            f"direct dependents: {record['direct_dependent_count']}"
        )

        is_selected = package == selected_package
        net.add_node(
            package,
            label=package,
            title=tooltip,
            color={
                "background": color,
                "border": COLOR_SELECTED_BORDER if is_selected else "#34495e",
            },
            borderWidth=6 if is_selected else 1,
            size=15 + 35 * record["impact_score"] + (12 if is_selected else 0),
            shape="star" if is_selected else "dot",
        )

    for source, target in graph.edges:
        is_path_edge = (source, target) in highlight_edges
        net.add_edge(
            source, target,
            color=COLOR_PATH_EDGE if is_path_edge else COLOR_NORMAL_EDGE,
            width=5 if is_path_edge else 1,
            arrows="to",
        )

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as handle:
        handle.write(net.generate_html(notebook=False))
        path = handle.name

    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# 8. STREAMLIT UI
# ---------------------------------------------------------------------------

def render_reasoning_breakdown(record):
    left, right = st.columns(2)

    with left:
        if record["cvss"] is not None:
            st.markdown(f"**CVSS severity:** {record['cvss']} / 10 ({record['cve']})")
            st.caption(record["summary"] or "")
        else:
            st.markdown("**CVSS severity:** no known vulnerability")
        st.markdown(f"**Layer:** {record['layer']}")
        st.markdown(f"**Direct dependents:** {record['direct_dependent_count']}")
        if record["direct_dependents"]:
            st.caption(", ".join(record["direct_dependents"]))

    with right:
        st.markdown(f"**Impact score:** {record['impact_score']:.3f}")
        st.markdown(f"**Packages affected if compromised:** {record['affected_count']}")
        if record["risk_score"] is not None:
            st.markdown(
                f"**Risk score:** {record['cvss']} x {record['impact_score']:.3f} "
                f"= **{record['risk_score']:.2f}**"
            )
        else:
            st.markdown("**Risk score:** n/a (no active advisory to multiply)")

    st.markdown("**Affected downstream packages:**")
    if record["affected_packages"]:
        st.write(", ".join(record["affected_packages"]))
    else:
        st.write("none - nothing depends on this package")


def main():
    st.set_page_config(page_title="Ripple Effect: OSS Supply Chain Risk", layout="wide")

    st.title("Open Source Supply Chains: The Ripple Effect")
    st.markdown(
        "Maps dependency relationships, traces propagation paths, simulates how a "
        "single compromised package spreads, and ranks what to fix first - showing "
        "its reasoning, not just a score."
    )

    graph = build_dependency_graph()
    analysis = analyze_ecosystem(graph)
    active_risk = get_active_risk_list(analysis)
    watchlist = get_structural_watchlist(analysis)
    watchlist_names = {r["package"] for r in watchlist}

    # ---- SIDEBAR CONTROLS ----
    st.sidebar.header("Simulation controls")
    package_options = sorted(graph.nodes)
    default_index = package_options.index("http-client") if "http-client" in package_options else 0
    selected_package = st.sidebar.selectbox(
        "Simulated compromise point", package_options, index=default_index
    )
    transmission_probability = st.sidebar.slider(
        "Transmission probability per dependency edge",
        min_value=0.0, max_value=1.0, value=0.6, step=0.05,
        help="Chance a compromise actually propagates across one edge. Below "
             "1.0 because pinned versions, lockfiles and review often stop it.",
    )
    simulation_runs = st.sidebar.number_input(
        "Monte Carlo runs", min_value=100, max_value=5000, value=800, step=100
    )
    random_seed = st.sidebar.number_input(
        "Random seed (for reproducible demos)", min_value=0, max_value=9999, value=42, step=1
    )
    st.sidebar.markdown("---")
    st.sidebar.caption(
        f"Ecosystem: {graph.number_of_nodes()} packages, "
        f"{graph.number_of_edges()} dependency edges, "
        f"{len(KNOWN_VULNERABILITIES)} known vulnerabilities."
    )
    random.seed(int(random_seed))

    # ---- PROPAGATION PATHS (computed early so the graph section can use them) ----
    paths = get_propagation_paths(graph, selected_package)

    st.header("1. Dependency graph & propagation path:")
    st.caption(
        "Arrows point from a package to what it depends on. Node size grows with "
        "impact score. Red = active risk, yellow = structural watchlist, "
        "green = safe. Purple star = selected compromise point. "
        "Pick a target below to trace the exact path in orange."
    )

    if paths:
        target_package = st.selectbox(
            "Trace propagation path to:", sorted(paths.keys()), key="path_target"
        )
        traced_path = paths[target_package]
        st.markdown(" → ".join(f"**{p}**" for p in traced_path))
        st.caption(f"{len(traced_path) - 1} hop(s) from the compromised package.")
        highlight_edges = path_to_edge_set(traced_path)
    else:
        st.info(f"'{selected_package}' has no downstream dependents to trace.")
        highlight_edges = set()

    graph_html = build_pyvis_html(
        graph, analysis, watchlist_names, selected_package, highlight_edges
    )
    components.html(graph_html, height=620, scrolling=True)

    # ---- ACTIVE RISK ----
    st.header("2. Active Risk:")
    st.caption("Known vulnerability, ranked by CVSS x impact score (not CVSS alone).")
    if active_risk:
        st.dataframe(
            pd.DataFrame([
                {
                    "Package": r["package"], "CVE": r["cve"], "CVSS": r["cvss"],
                    "Impact score": round(r["impact_score"], 3),
                    "Risk score": round(r["risk_score"], 2),
                    "Affected packages": r["affected_count"], "Action": "Patch now.",
                }
                for r in active_risk
            ]),
            use_container_width=True, hide_index=True,
        )
        for rank, record in enumerate(active_risk, start=1):
            with st.expander(f"Reasoning #{rank}: {record['package']} (risk score {record['risk_score']:.2f})"):
                render_reasoning_breakdown(record)
    else:
        st.info("No known vulnerabilities in this ecosystem snapshot.")

    # ---- STRUCTURAL WATCHLIST ----
    st.header("3. Structural Watchlist:")
    st.caption(
        "No known issue today, but would be catastrophic if compromised "
        f"(impact score > {STRUCTURAL_WATCHLIST_THRESHOLD}). The xz-utils backdoor "
        "had no CVE before discovery - a CVSS-only scanner would have called it "
        "clean. This list is what catches that class of risk."
    )
    if watchlist:
        st.dataframe(
            pd.DataFrame([
                {
                    "Package": r["package"], "Known CVE": "none",
                    "Impact score": round(r["impact_score"], 3),
                    "Affected packages": r["affected_count"],
                    "Direct dependents": r["direct_dependent_count"],
                    "Action": "Monitor / harden.",
                }
                for r in watchlist
            ]),
            use_container_width=True, hide_index=True,
        )
        for rank, record in enumerate(watchlist, start=1):
            with st.expander(
                f"Reasoning #{rank}: {record['package']} "
                f"(impact {record['impact_score']:.2f}, {record['direct_dependent_count']} direct dependents)"
            ):
                render_reasoning_breakdown(record)
                st.info(
                    "Note the asymmetry: few direct dependents, but a large indirect "
                    "blast radius. Traditional per-package scanners cannot see this."
                )
    else:
        st.info("No unflagged high-impact packages above the threshold.")

    # ---- MONTE CARLO SIMULATION ----
    st.header("4. Propagation simulation:")
    st.caption(
        f"If **{selected_package}** were compromised: deterministic worst case vs. "
        "probabilistic expected case."
    )
    results = run_monte_carlo(graph, selected_package, transmission_probability, int(simulation_runs))

    col_a, col_b, col_c = st.columns(3)
    col_a.metric(
        "Deterministic blast radius (worst case)",
        f"{results['deterministic_affected']} pkgs",
        f"{results['deterministic_percent']:.1f}% of ecosystem",
    )
    col_b.metric(
        f"Monte Carlo average (p={transmission_probability})",
        f"{results['average_affected']:.1f} pkgs",
        f"{results['average_percent']:.1f}% of ecosystem",
    )
    col_c.metric(
        f"Observed range over {results['runs']} runs",
        f"{results['min_affected']}-{results['max_affected']} pkgs",
    )
    st.markdown(
        "**Why the two numbers differ:** the deterministic figure assumes every "
        "dependency edge transmits with certainty. The Monte Carlo figure rolls a "
        f"{transmission_probability:.0%} chance per edge, modelling pinned versions, "
        "lockfiles and review that often stop propagation. Plan capacity around the "
        "average; plan worst-case response around the blast radius."
    )

    st.subheader("Distribution across simulation runs")
    st.bar_chart(build_histogram_table(results["per_run_affected"]))

    # ---- MITIGATION PRIORITY ----
    st.header("5. Mitigation priority ranking:")
    st.caption(
        "Ranked by share of total ecosystem risk removed, not raw severity - so "
        "limited engineering time goes where it buys the most safety."
    )
    mitigations = rank_mitigations(active_risk)
    if mitigations:
        total_risk = sum(r["risk_score"] for r in active_risk)
        st.markdown(f"Total measured ecosystem risk: **{total_risk:.2f}**")
        for rank, item in enumerate(mitigations, start=1):
            st.markdown(
                f"{rank}. Patch **'{item['package']}'** -> removes "
                f"**{item['risk_removed_percent']:.1f}%** of total ecosystem risk "
                f"(CVSS {item['cvss']}, risk score {item['risk_score']:.2f}, "
                f"{item['affected_count']} packages downstream)"
            )
    else:
        st.info("Nothing to patch - no active advisories.")


if __name__ == "__main__":
    main()