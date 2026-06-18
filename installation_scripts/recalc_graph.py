#!/usr/bin/env python3
"""
Threat Graph Recalculator and Compiler
Sourced and compiled from harvested investigation telemetry in investigations/.
Generates knowledge_graph.json, knowledge_graph.dot, and knowledge_graph.html.
"""

import argparse
import glob
import json
import os
import re
from pathlib import Path


def clean_label(val):
    if not val:
        return ""
    # Strip asterisks, spaces, backslashes, and trailing dollar signs
    cleaned = val.strip("* \t\n\r\\$")
    # Handle fully-qualified hostnames by keeping them or keeping short names
    return cleaned


def extract_uuid(val):
    match = re.search(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        val,
    )
    return match.group(0) if match else val


def parse_investigation_file(filepath):
    """Parse a single investigation JSON and extract nodes and edges."""
    with open(filepath) as f:
        data = json.load(f)

    inv_name = data.get("name", "")
    inv_id = (
        inv_name.split("/")[-1]
        if "/" in inv_name
        else extract_uuid(os.path.basename(filepath))
    )

    nodes = {}
    edges = []

    # 1. Add root Investigation Node
    inv_node_id = f"inv:{inv_id}"
    nodes[inv_node_id] = {
        "id": inv_node_id,
        "label": "Investigation",
        "properties": {
            "id": inv_id,
            "displayName": data.get("displayName", "Unknown Investigation"),
            "verdict": data.get("verdict", "UNKNOWN"),
            "confidence": data.get("confidence", "N/A"),
        },
    }

    # Track entities seen in this investigation to link with INVOLVES
    local_entities = set()

    def add_entity(entity_id, label, props):
        if entity_id == inv_node_id:
            return
        local_entities.add(entity_id)
        if entity_id not in nodes:
            nodes[entity_id] = {"id": entity_id, "label": label, "properties": props}

    # Regular expressions for entity extraction from text
    # Matches: wrk-shasek, activedir, wins-d19, and full FQDNs
    host_pattern = re.compile(
        r"\b(wrk-[a-zA-Z0-9.-]+|activedir[a-zA-Z0-9.-]*|wins-[a-zA-Z0-9.-]+)\b",
        re.IGNORECASE,
    )
    # Matches: tim.smith, frank.kolzig, jsmith, lisa.walker, etc.
    user_pattern = re.compile(
        r"\b([a-zA-Z]+[.-][a-zA-Z]+|jsmith|lisawalker|timsmith|frankkolzig)\b",
        re.IGNORECASE,
    )
    # Matches: filenames ending in .exe, .ps1, .csproj, .dll, .zip, .bat, .cmd
    file_pattern = re.compile(
        r"\b([a-zA-Z0-9_-]+\.(?:exe|ps1|csproj|dll|zip|bat|cmd|ni\.dll))\b",
        re.IGNORECASE,
    )
    # Matches: IP addresses
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    # Matches: external domains
    domain_pattern = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b")

    # Helper to parse text and extract entities
    def extract_from_text(text, context_host=None):
        if not text:
            return

        # Extract hosts
        for host in host_pattern.findall(text):
            clean_h = clean_label(host).lower()
            if (
                clean_h
                and not clean_h.endswith(".exe")
                and not clean_h.endswith(".dll")
                and not clean_h.endswith(".zip")
            ):
                add_entity(f"host:{clean_h}", "Host", {"name": clean_h})

        # Extract users
        for user in user_pattern.findall(text):
            clean_u = clean_label(user).lower()
            # Ignore false positives
            if clean_u and clean_u not in [
                "temp",
                "windows",
                "system32",
                "github.com",
                "codeload.github",
                "github",
                "master.zip",
                "archive.zip",
                "spray.ps1",
                "mimikatz",
            ]:
                add_entity(f"user:{clean_u}", "User", {"name": clean_u})
                if context_host:
                    edges.append(
                        {
                            "source": f"user:{clean_u}",
                            "target": f"host:{context_host}",
                            "type": "LOGGED_ON_TO",
                        }
                    )

        # Extract files
        for f_name in file_pattern.findall(text):
            clean_f = clean_label(f_name).lower()
            if clean_f and clean_f not in [
                "powershell.exe",
                "cmd.exe",
                "conhost.exe",
                "net.exe",
            ]:
                add_entity(f"file:{clean_f}", "File", {"name": clean_f})
                if context_host:
                    edges.append(
                        {
                            "source": f"file:{clean_f}",
                            "target": f"host:{context_host}",
                            "type": "EXECUTED_ON",
                        }
                    )

        # Extract IPs
        for ip in ip_pattern.findall(text):
            if ip not in ["0.0.0.0", "255.255.255.255"]:  # noqa: S104
                # If internal subnet 10.x, or loopback/broadcast skip or classify
                label = "NetworkAddress"
                add_entity(f"network address:{ip}", label, {"name": ip})
                if context_host:
                    edges.append(
                        {
                            "source": f"host:{context_host}",
                            "target": f"network address:{ip}",
                            "type": "CONNECTED_TO",
                        }
                    )

        # Extract domains
        for dom in domain_pattern.findall(text):
            clean_d = clean_label(dom).lower()
            if (
                clean_d
                and clean_d not in ["localhost", "stackedpads.local"]
                and not ip_pattern.match(clean_d)
            ):
                # Ensure it's not a file extension false positive
                if not any(
                    clean_d.endswith(ext)
                    for ext in [
                        ".exe",
                        ".ps1",
                        ".dll",
                        ".zip",
                        ".csproj",
                        ".bat",
                        ".cmd",
                    ]
                ):
                    add_entity(f"domain:{clean_d}", "Domain", {"name": clean_d})
                    if context_host:
                        edges.append(
                            {
                                "source": f"host:{context_host}",
                                "target": f"domain:{clean_d}",
                                "type": "CONNECTED_TO",
                            }
                        )

    # Parse main summary and display name
    extract_from_text(data.get("summary", ""))
    extract_from_text(data.get("displayName", ""))

    # Parse next steps
    for step in data.get("nextSteps", []):
        extract_from_text(step.get("title", ""))

    # Parse investigation steps
    for step in data.get("investigationSteps", []):
        description = step.get("description", "")
        summary = step.get("analysisSummary", "")

        # Try to identify a host context from step summary or description
        step_host = None
        host_matches = host_pattern.findall(summary + " " + description)
        if host_matches:
            step_host = clean_label(host_matches[0]).lower()

        extract_from_text(summary, context_host=step_host)
        extract_from_text(description, context_host=step_host)

        # Process tree parsing
        src_meta = step.get("sourceMetadata", {})
        if "processTree" in src_meta:
            pt_data = src_meta.get("processTree", {})
            pt_text = (
                pt_data.get("processTree", "") if isinstance(pt_data, dict) else pt_data
            )
            if isinstance(pt_text, str):
                lines = pt_text.split("\n")
                process_stack = []

                for line in lines:
                    if not line.strip():
                        continue

                    # Determine indent level to map parent-child processes
                    indent = len(line) - len(line.lstrip(" *-\t"))

                    # Extract process name, path, PID, and Command Line
                    # e.g.: * C:\Windows\System32\RuntimeBroker.exe (PID: 2352)
                    proc_match = re.search(
                        r"(?:[\w]:)?\\[^\\]+\.exe", line, re.IGNORECASE
                    )
                    pid_match = re.search(r"PID:\s*(\d+)", line, re.IGNORECASE)
                    cmd_match = re.search(
                        r"command line:\s*([^\)]+)", line, re.IGNORECASE
                    )
                    sha_match = re.search(
                        r"Sha256:\s*([a-fA-F0-9]{64})", line, re.IGNORECASE
                    )

                    if proc_match:
                        full_path = proc_match.group(0)
                        proc_name = os.path.basename(full_path).lower()
                        pid = pid_match.group(1) if pid_match else "unknown"
                        cmd_line = cmd_match.group(1).strip() if cmd_match else ""
                        sha = sha_match.group(1) if sha_match else ""

                        file_node_id = f"file:{proc_name}"
                        props = {
                            "name": proc_name,
                            "path": full_path,
                            "pid": pid,
                        }
                        if cmd_line:
                            props["command_line"] = cmd_line
                        if sha:
                            props["sha256"] = sha

                        add_entity(file_node_id, "File", props)

                        if step_host:
                            edges.append(
                                {
                                    "source": file_node_id,
                                    "target": f"host:{step_host}",
                                    "type": "EXECUTED_ON",
                                }
                            )

                        # Parent-Child mapping using indentation
                        while process_stack and process_stack[-1]["indent"] >= indent:
                            process_stack.pop()

                        if process_stack:
                            parent = process_stack[-1]
                            edges.append(
                                {
                                    "source": parent["node_id"],
                                    "target": file_node_id,
                                    "type": "SPAWNED",
                                }
                            )

                        process_stack.append(
                            {"indent": indent, "node_id": file_node_id}
                        )

                    # Extract network connections in process tree
                    # e.g.: NETWORK_CONNECTION to IP [140.82.113.4] on port 443
                    net_conn_match = re.search(
                        r"NETWORK_CONNECTION to IP\s*\[?([0-9.]+)\]?", line
                    )
                    if net_conn_match:
                        dest_ip = net_conn_match.group(1)
                        ip_node_id = f"network address:{dest_ip}"
                        add_entity(ip_node_id, "NetworkAddress", {"name": dest_ip})
                        if step_host:
                            edges.append(
                                {
                                    "source": f"host:{step_host}",
                                    "target": ip_node_id,
                                    "type": "CONNECTED_TO",
                                }
                            )

                    # Extract file creations in process tree
                    # e.g.: FILE_CREATION with filename g:\archive.zip
                    file_creat_match = re.search(
                        r"FILE_CREATION with filename\s*(.+)", line, re.IGNORECASE
                    )
                    if file_creat_match:
                        file_path = file_creat_match.group(1).strip()
                        file_name = os.path.basename(file_path).lower()
                        if file_name:
                            file_node_id = f"file:{file_name}"
                            add_entity(
                                file_node_id,
                                "File",
                                {"name": file_name, "path": file_path},
                            )
                            if step_host:
                                edges.append(
                                    {
                                        "source": file_node_id,
                                        "target": f"host:{step_host}",
                                        "type": "EXECUTED_ON",
                                    }
                                )

        # Parse query codes in steps
        query_data = src_meta.get("query", {})
        if isinstance(query_data, dict) and "queryCode" in query_data:
            q_code = query_data.get("queryCode", "")
            # Look for indicators inside the query code
            extract_from_text(q_code, context_host=step_host)

    # Link all local entities with the parent Investigation
    for ent_id in local_entities:
        edges.append({"source": inv_node_id, "target": ent_id, "type": "INVOLVES"})

    return list(nodes.values()), edges


def generate_dot(nodes, edges):
    """Generate Graphviz DOT content."""
    lines = ["digraph G {", '    node [style=filled, fontname="Outfit"];']

    # Colors matching the D3.js premium theme
    colors = {
        "Investigation": "orange",
        "Host": "lightblue",
        "User": "lightgreen",
        "File": "pink",
        "Domain": "khaki",
        "NetworkAddress": "lightgrey",
        "Alert": "salmon",
        "Case": "mediumpurple",
    }

    for node in nodes:
        nid = (
            node["id"]
            .replace(":", "_")
            .replace(".", "_")
            .replace("-", "_")
            .replace("\\", "_")
        )
        label = (
            node["properties"].get("name")
            or node["properties"].get("displayName")
            or node["id"]
        )
        label_clean = label.replace('"', '\\"')
        color = colors.get(node["label"], "white")
        lines.append(
            f'    {nid} [label="{label_clean}", fillcolor={color}, shape=box];'
        )

    for edge in edges:
        src = (
            edge["source"]
            .replace(":", "_")
            .replace(".", "_")
            .replace("-", "_")
            .replace("\\", "_")
        )
        tgt = (
            edge["target"]
            .replace(":", "_")
            .replace(".", "_")
            .replace("-", "_")
            .replace("\\", "_")
        )
        etype = edge["type"]
        lines.append(f'    {src} -> {tgt} [label="{etype}"];')

    lines.append("}")
    return "\n".join(lines)


def generate_html(graph_data_json):
    """Generate D3.js force-directed HTML visualization using premium styling."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SecOps Investigations Knowledge Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            background: linear-gradient(135deg, #0a0b10 0%, #161824 100%);
            color: #f3f4f6;
            font-family: 'Outfit', sans-serif;
            overflow: hidden;
            height: 100vh;
        }}
        header {{
            position: absolute;
            top: 20px;
            left: 20px;
            z-index: 10;
            pointer-events: none;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #ff7b00, #ffae00);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{
            font-size: 13px;
            color: #9ca3af;
            font-weight: 400;
            margin-top: 4px;
        }}
        #canvas {{
            width: 100vw;
            height: 100vh;
        }}
        .sidebar {{
            position: absolute;
            top: 20px;
            right: 20px;
            width: 380px;
            max-height: calc(100vh - 40px);
            background: rgba(30, 32, 50, 0.85);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 24px;
            overflow-y: auto;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            display: none;
            z-index: 100;
        }}
        .sidebar-title {{
            font-size: 20px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 8px;
        }}
        .sidebar-label {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 20px;
        }}
        .prop-section {{
            margin-bottom: 24px;
        }}
        .prop-title {{
            font-size: 11px;
            color: #9ca3af;
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }}
        .prop-value {{
            font-size: 14px;
            color: #e5e7eb;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.2);
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }}
        .links-line {{
            stroke: rgba(255, 255, 255, 0.15);
            stroke-width: 1.5px;
        }}
        .links-line.active {{
            stroke: #ffae00;
            stroke-width: 2.5px;
        }}
        .node-circle {{
            stroke: #0a0b10;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .node-text {{
            fill: #9ca3af;
            font-size: 10px;
            font-weight: 400;
            pointer-events: none;
            text-anchor: middle;
        }}
    </style>
</head>
<body>
    <header>
        <h1>SecOps Investigations Threat Graph</h1>
        <div class="subtitle">Interactive Live Visualizer & Relationship Traversal</div>
    </header>

    <svg id="canvas"></svg>

    <div id="sidebar" class="sidebar">
        <div id="sidebar-title" class="sidebar-title">Entity Details</div>
        <div id="sidebar-label" class="sidebar-label">Host</div>
        <div id="sidebar-props"></div>
    </div>

    <script>
        const graphData = {graph_data_json};

        // Graph color system
        const colors = {{
            "Investigation": d3.scaleOrdinal().range(["#ff7b00"]),
            "Host": d3.scaleOrdinal().range(["#00d2ff"]),
            "User": d3.scaleOrdinal().range(["#00ff66"]),
            "File": d3.scaleOrdinal().range(["#ff0066"]),
            "Domain": d3.scaleOrdinal().range(["#ffea00"]),
            "NetworkAddress": d3.scaleOrdinal().range(["#a0a0a0"]),
            "Alert": d3.scaleOrdinal().range(["#ff4444"]),
            "Case": d3.scaleOrdinal().range(["#9b51e0"])
        }};

        const svg = d3.select("#canvas");
        const width = window.innerWidth;
        const height = window.innerHeight;

        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.edges).id(d => d.id).distance(120))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(25));

        const g = svg.append("g");

        // Zoom & Pan
        svg.call(d3.zoom().on("zoom", (event) => {{
            g.attr("transform", event.transform);
        }}));

        // Create edges
        const link = g.append("g")
            .selectAll("line")
            .data(graphData.edges)
            .enter().append("line")
            .attr("class", "links-line");

        // Create nodes
        const node = g.append("g")
            .selectAll("g")
            .data(graphData.nodes)
            .enter().append("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended))
            .on("click", (event, d) => {{
                event.stopPropagation();
                showSidebar(d);
                highlightNode(d);
            }});

        node.append("circle")
            .attr("r", d => d.label === "Investigation" ? 16 : 10)
            .attr("class", "node-circle")
            .attr("fill", d => colors[d.label] ? colors[d.label](d) : "#ffffff");

        node.append("text")
            .attr("dy", 22)
            .attr("class", "node-text")
            .text(d => d.properties.name || d.properties.displayName || d.id.split(":")[1]);

        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("transform", d => `translate(${{d.x}}, ${{d.y}})`);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}

        svg.on("click", () => {{
            hideSidebar();
            resetHighlights();
        }});

        function showSidebar(d) {{
            const sidebar = d3.select("#sidebar");
            sidebar.style("display", "block");

            d3.select("#sidebar-title").text(d.properties.name || d.properties.displayName || d.id);

            const labelNode = d3.select("#sidebar-label");
            labelNode.text(d.label)
                .style("background", colors[d.label] ? colors[d.label](d) : "#ffffff")
                .style("color", "#0a0b10");

            const propsDiv = d3.select("#sidebar-props");
            propsDiv.html("");

            for (const [key, val] of Object.entries(d.properties)) {{
                const section = propsDiv.append("div").attr("class", "prop-section");
                section.append("div").attr("class", "prop-title").text(key);
                section.append("div").attr("class", "prop-value").text(val);
            }}
        }}

        function hideSidebar() {{
            d3.select("#sidebar").style("display", "none");
        }}

        function highlightNode(selectedNode) {{
            node.style("opacity", d => {{
                if (d.id === selectedNode.id) return 1.0;
                const isNeighbor = graphData.edges.some(e =>
                    (e.source.id === selectedNode.id && e.target.id === d.id) ||
                    (e.target.id === selectedNode.id && e.source.id === d.id)
                );
                return isNeighbor ? 0.9 : 0.15;
            }});

            link
                .style("stroke-opacity", e => (e.source.id === selectedNode.id || e.target.id === selectedNode.id) ? 0.8 : 0.05)
                .attr("class", e => (e.source.id === selectedNode.id || e.target.id === selectedNode.id) ? "links-line active" : "links-line");
        }}

        function resetHighlights() {{
            node.style("opacity", 1.0);
            link
                .style("stroke-opacity", 0.3)
                .attr("class", "links-line");
        }}
    </script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Recalculate SOC Threat Graph from harvested JSON telemetry."
    )
    parser.add_argument(
        "--dir",
        default="investigations",
        help="Directory containing harvested JSONs.",
    )
    parser.add_argument(
        "--output-json",
        default="investigations/knowledge_graph.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--output-dot",
        default="investigations/knowledge_graph.dot",
        help="Output Graphviz DOT path.",
    )
    parser.add_argument(
        "--output-html",
        default="investigations/knowledge_graph.html",
        help="Output HTML path.",
    )
    args = parser.parse_args()

    search_dir = Path(args.dir)
    if not search_dir.exists():
        print(f"Error: Directory {search_dir} does not exist.")
        return

    print(f"Scanning {search_dir} for investigation JSON files...")
    json_files = glob.glob(os.path.join(search_dir, "*.json"))

    all_nodes = {}
    all_edges = []

    parsed_count = 0
    for f_path in json_files:
        filename = os.path.basename(f_path)
        # Skip special metadata/graph files
        if filename in ["knowledge_graph.json", "metadata.json", "package.json"]:
            continue
        # Skip case or alert files if any (we focus on raw investigation JSONs or standard ones)
        if filename.startswith("case_") or filename.startswith("alert_"):
            continue

        try:
            nodes, edges = parse_investigation_file(f_path)
            # Merge nodes
            for node in nodes:
                nid = node["id"]
                if nid in all_nodes:
                    # Update properties
                    all_nodes[nid]["properties"].update(node["properties"])
                else:
                    all_nodes[nid] = node
            # Merge edges
            all_edges.extend(edges)
            parsed_count += 1
        except Exception as e:
            print(f"Warning: Failed to parse {filename}: {e}")

    # De-duplicate edges
    unique_edges = []
    seen_edges = set()
    for edge in all_edges:
        # Resolve source/target if they are dictionary objects (due to d3 binding in memory on subsequent runs, though here it's static)
        src = edge["source"]
        tgt = edge["target"]
        etype = edge["type"]
        edge_key = (src, tgt, etype)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            unique_edges.append(edge)

    graph_data = {"nodes": list(all_nodes.values()), "edges": unique_edges}

    # Save JSON
    print(f"Successfully compiled {parsed_count} investigations.")
    print(
        f"Found {len(graph_data['nodes'])} nodes and {len(graph_data['edges'])} unique edges."
    )

    # Create parent directories if they don't exist
    os.makedirs(os.path.dirname(args.output_json), exist_ok=True)

    with open(args.output_json, "w") as f:
        json.dump(graph_data, f, indent=2)
    print(f"Saved compiled JSON graph to: {args.output_json}")

    # Save DOT
    dot_content = generate_dot(graph_data["nodes"], graph_data["edges"])
    with open(args.output_dot, "w") as f:
        f.write(dot_content)
    print(f"Saved Graphviz DOT graph to: {args.output_dot}")

    # Save HTML
    html_content = generate_html(json.dumps(graph_data))
    with open(args.output_html, "w") as f:
        f.write(html_content)
    print(f"Saved premium D3.js interactive graph to: {args.output_html}")
    print("Graph recalculation complete!")


if __name__ == "__main__":
    main()
