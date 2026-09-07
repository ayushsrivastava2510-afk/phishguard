"""
attribution_graph.py
---------------------
Identity Correlation and Campaign Attribution Engine.
Reconstructs shared attacker infrastructure across multiple forensic cases:
  - Correlates shared originating IP subnets, ASN providers, and sender domains
  - Detects coordinated Advanced Persistent Threat (APT) / Phishing campaigns
  - Generates interactive Vis.js physical topological graph maps and static clusters
"""

import networkx as nx
import matplotlib
matplotlib.use("Agg")  # render to image buffer, no GUI needed
import matplotlib.pyplot as plt
import io


def build_attribution_graph(email_records):
    """
    email_records: list of dicts, each like:
        {
            "id": "email_1",
            "subject": "...",
            "from_domain": "paypa1-support.com",
            "originating_ip": "45.155.204.12",
            "risk_score": 88,
        }

    Builds a graph where:
      - Each email is a node
      - Each unique domain is a node
      - Each unique IP is a node
      - Edges connect an email to its domain and its IP
    If two emails share a domain or IP, they end up connected through
    that shared node -- visually revealing a campaign cluster.
    """
    G = nx.Graph()

    for record in email_records:
        email_node = f"email::{record['id']}"
        G.add_node(email_node, kind="email", label=record.get("subject", record["id"])[:30])

        domain = record.get("from_domain")
        if domain:
            domain_node = f"domain::{domain}"
            G.add_node(domain_node, kind="domain", label=domain)
            G.add_edge(email_node, domain_node)

        ip = record.get("originating_ip")
        if ip:
            ip_node = f"ip::{ip}"
            G.add_node(ip_node, kind="ip", label=ip)
            G.add_edge(email_node, ip_node)

    return G


def find_campaign_clusters(G):
    """
    A 'campaign' = a connected component with more than one email node.
    Returns a list of email-id lists, one per detected campaign.
    """
    clusters = []
    for component in nx.connected_components(G):
        email_ids = [
            n.split("::", 1)[1] for n in component
            if G.nodes[n]["kind"] == "email"
        ]
        if len(email_ids) > 1:
            clusters.append(email_ids)
    return clusters


def render_graph_image(G):
    """
    Renders the graph to a PNG image (in-memory buffer) for display
    in the Streamlit dashboard. Colors nodes by type with an explicit legend.
    """
    if G.number_of_nodes() == 0:
        return None

    color_map = {"email": "#6B46C1", "domain": "#DD6B20", "ip": "#2B6CB0"}
    node_colors = [color_map.get(G.nodes[n]["kind"], "#718096") for n in G.nodes]
    labels = {n: G.nodes[n]["label"] for n in G.nodes}

    fig, ax = plt.subplots(figsize=(8, 5.5))
    pos = nx.spring_layout(G, seed=42, k=1.0)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1500, ax=ax, alpha=0.9)
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#CBD5E0", width=2.0)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=7.5, ax=ax, font_weight="bold", font_color="#1A202C")

    # Legend elements
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', label='Email Incident', markerfacecolor='#6B46C1', markersize=10),
        Line2D([0], [0], marker='o', color='w', label='Domain Node', markerfacecolor='#DD6B20', markersize=10),
        Line2D([0], [0], marker='o', color='w', label='Originating IP', markerfacecolor='#2B6CB0', markersize=10),
    ]
    ax.legend(handles=legend_elements, loc='upper left', framealpha=0.8, fontsize=8)

    ax.axis("off")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, transparent=False, facecolor="#F8FAFC")
    plt.close(fig)
    buf.seek(0)
    return buf


def generate_interactive_graph_html(G):
    """
    Generates a dynamic, physics-enabled HTML5 network visualization using Vis.js.
    Allows user to drag nodes, zoom, pan, and click to inspect shared campaign infrastructure.
    """
    if G.number_of_nodes() == 0:
        return "<div style='color:#94a3b8; padding:20px;'>No graph nodes to display.</div>"

    import json

    nodes = []
    edges = []

    for n in G.nodes:
        kind = G.nodes[n].get("kind", "unknown")
        lbl = G.nodes[n].get("label", n)

        if kind == "email":
            color = {"background": "#8b5cf6", "border": "#c4b5fd", "highlight": {"background": "#7c3aed", "border": "#ffffff"}}
            shape = "dot"
            size = 24
            title = f"Email Incident: {lbl}"
        elif kind == "domain":
            color = {"background": "#f97316", "border": "#fdba74", "highlight": {"background": "#ea580c", "border": "#ffffff"}}
            shape = "diamond"
            size = 20
            title = f"Sender Domain: {lbl}"
        elif kind == "ip":
            color = {"background": "#ef4444", "border": "#fca5a5", "highlight": {"background": "#dc2626", "border": "#ffffff"}}
            shape = "hexagon"
            size = 26
            title = f"Attacker Origin IP: {lbl} (Shared Infrastructure)"
        else:
            color = {"background": "#64748b", "border": "#94a3b8", "highlight": {"background": "#475569", "border": "#ffffff"}}
            shape = "dot"
            size = 18
            title = lbl

        nodes.append({
            "id": n,
            "label": lbl[:25] + ("..." if len(lbl) > 25 else ""),
            "shape": shape,
            "size": size,
            "color": color,
            "font": {"color": "#f8fafc", "size": 11, "face": "Inter, sans-serif"},
            "title": title,
        })

    for u, v in G.edges:
        edges.append({
            "from": u,
            "to": v,
            "color": {"color": "#64748b", "highlight": "#38bdf8", "opacity": 0.8},
            "width": 2,
            "smooth": {"type": "continuous"},
        })

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style>
        body, html {{
          margin: 0; padding: 0; width: 100%; height: 100%;
          background: #0b1329; overflow: hidden;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        #mynetwork {{
          width: 100%; height: 100%;
        }}
        .legend {{
          position: absolute; top: 12px; left: 14px;
          background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(8px);
          border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px;
          padding: 8px 14px; font-size: 11px; color: #94a3b8; z-index: 10;
          display: flex; gap: 14px; align-items: center;
        }}
        .legend-item {{ display: flex; align-items: center; gap: 6px; }}
        .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
        .hint {{
          position: absolute; bottom: 10px; right: 14px;
          background: rgba(15, 23, 42, 0.75); border-radius: 6px;
          padding: 4px 10px; font-size: 10px; color: #64748b;
        }}
      </style>
    </head>
    <body>
      <div class="legend">
        <div class="legend-item"><span class="dot" style="background:#8b5cf6;"></span> <span>Email Incident</span></div>
        <div class="legend-item"><span class="dot" style="background:#f97316;"></span> <span>Domain Node</span></div>
        <div class="legend-item"><span class="dot" style="background:#ef4444;"></span> <span>Origin IP (Attacker Node)</span></div>
      </div>
      <div class="hint">💡 Drag nodes to interact &bull; Scroll to zoom</div>
      <div id="mynetwork"></div>

      <script type="text/javascript">
        var container = document.getElementById('mynetwork');
        var data = {{
          nodes: new vis.DataSet({nodes_json}),
          edges: new vis.DataSet({edges_json})
        }};
        var options = {{
          physics: {{
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
              gravitationalConstant: -40,
              centralGravity: 0.015,
              springLength: 100,
              springConstant: 0.08,
              damping: 0.8
            }},
            maxVelocity: 40,
            minVelocity: 0.1
          }},
          interaction: {{
            hover: true,
            tooltipDelay: 150,
            zoomView: true,
            dragView: true
          }}
        }};
        var network = new vis.Network(container, data, options);
      </script>
    </body>
    </html>
    """
    return html


if __name__ == "__main__":
    # Self-test with fake records -- two emails share the same IP,
    # simulating a real campaign.
    test_records = [
        {"id": "email_1", "subject": "PayPal verify now", "from_domain": "paypa1-support.com",
         "originating_ip": "45.155.204.12", "risk_score": 88},
        {"id": "email_2", "subject": "Microsoft billing failed", "from_domain": "micros0ft-alerts.net",
         "originating_ip": "45.155.204.12", "risk_score": 82},
        {"id": "email_3", "subject": "Team lunch Thursday?", "from_domain": "partnerfirm.com",
         "originating_ip": "209.85.220.41", "risk_score": 5},
    ]

    G = build_attribution_graph(test_records)
    print(f"Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")

    clusters = find_campaign_clusters(G)
    print(f"Detected {len(clusters)} campaign cluster(s):")
    for c in clusters:
        print(f"  -> {c}")

    img_buf = render_graph_image(G)
    if img_buf:
        with open("attribution_test_output.png", "wb") as f:
            f.write(img_buf.read())
        print("Saved test image -> attribution_test_output.png")
