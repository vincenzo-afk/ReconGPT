import { useMemo, useState } from "react";
import Network from "lucide-react/dist/esm/icons/network";
import Search from "lucide-react/dist/esm/icons/search";

export type GraphEvidence = { evidenceQuality: "direct" | "corroborated" | "context" | "lead"; leadStatus: "verified" | "review" | "unverified"; sourceCount: number; collectedAt?: string; limitations: string[]; findingCount: number };
export type GraphNode = { id: string; entityType: string; value: string; label: string; confidence: number; evidence?: GraphEvidence };
export type GraphEdge = { id: string; sourceEntityId: string; targetEntityId: string; relationType: string };

const nodeColors: Record<string, string> = { domain: "#33d6a6", subdomain: "#59a9ff", ip: "#fdad5f", email: "#c787ff", username: "#ff7fbb", organization: "#f7d65e", url: "#b7c2d2", certificate: "#62dcff", asn: "#ff8f70", phone: "#e1e7ef" };

function forceLayout(nodes: GraphNode[], edges: GraphEdge[]) {
  const width = 500; const height = 440; const connected = new Set(edges.flatMap(edge => [edge.sourceEntityId, edge.targetEntityId]));
  const points = nodes.map((node, index) => ({ ...node, x: 90 + ((index * 97) % 325), y: 65 + ((index * 61) % 310), vx: 0, vy: 0, degree: connected.has(node.id) ? 1 : 0 }));
  const byId = new Map(points.map(point => [point.id, point]));
  for (let tick = 0; tick < 150; tick += 1) {
    for (let a = 0; a < points.length; a += 1) for (let b = a + 1; b < points.length; b += 1) { const first = points[a]; const second = points[b]; const dx = first.x - second.x; const dy = first.y - second.y; const distanceSquared = Math.max(100, dx * dx + dy * dy); const force = 850 / distanceSquared; first.vx += dx * force; first.vy += dy * force; second.vx -= dx * force; second.vy -= dy * force; }
    for (const edge of edges) { const first = byId.get(edge.sourceEntityId); const second = byId.get(edge.targetEntityId); if (!first || !second) continue; const dx = second.x - first.x; const dy = second.y - first.y; const distance = Math.max(1, Math.hypot(dx, dy)); const force = (distance - 108) * 0.006; first.vx += dx / distance * force; first.vy += dy / distance * force; second.vx -= dx / distance * force; second.vy -= dy / distance * force; }
    for (const point of points) { point.vx += (width / 2 - point.x) * 0.002; point.vy += (height / 2 - point.y) * 0.002; point.x = Math.max(26, Math.min(width - 26, point.x + point.vx)); point.y = Math.max(26, Math.min(height - 26, point.y + point.vy)); point.vx *= .72; point.vy *= .72; }
  }
  return points;
}

export function ReconGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const [filter, setFilter] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const types = useMemo(() => Array.from(new Set(nodes.map(node => node.entityType))).sort(), [nodes]);
  const visible = useMemo(() => nodes.filter(node => filter === "all" || node.entityType === filter), [nodes, filter]);
  const positions = useMemo(() => forceLayout(visible, edges.filter(edge => visible.some(node => node.id === edge.sourceEntityId) && visible.some(node => node.id === edge.targetEntityId))), [visible, edges]);
  const byId = new Map(positions.map(node => [node.id, node]));
  const active = expanded ? nodes.find(node => node.id === expanded) : null;

  return <section className="panel graph-panel">
    <div className="panel-heading">
      <div><p className="eyebrow"><Network size={13} /> RELATIONSHIP MAP</p><h2>Entity graph</h2></div>
      <div className="graph-filter"><Search size={14} /><select aria-label="Filter entities by type" value={filter} onChange={event => setFilter(event.target.value)}><option value="all">All entities</option>{types.map(type => <option key={type} value={type}>{type}</option>)}</select></div>
    </div>
    {nodes.length === 0 ? <div className="empty-graph"><Network size={28} /><p>Run recon to map verified entities and their evidence-backed relationships.</p></div> : <div className="graph-layout">
      <svg className="entity-graph" viewBox="0 0 500 440" role="img" aria-label="Interactive entity relationship graph">
        <defs><radialGradient id="reconGlow"><stop stopColor="#1b3b42" stopOpacity=".75" /><stop offset="1" stopColor="#071017" stopOpacity="0" /></radialGradient></defs>
        <circle cx="250" cy="220" r="200" fill="url(#reconGlow)" />
        {edges.map(edge => { const source = byId.get(edge.sourceEntityId); const target = byId.get(edge.targetEntityId); return source && target ? <line key={edge.id} x1={source.x} y1={source.y} x2={target.x} y2={target.y} className="graph-edge" /> : null; })}
        {positions.map(node => <g key={node.id} className="graph-node" onClick={() => setExpanded(node.id === expanded ? null : node.id)} tabIndex={0} role="button" aria-label={`Expand ${node.label}`} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") setExpanded(node.id === expanded ? null : node.id); }}>
          <circle cx={node.x} cy={node.y} r={node.id === expanded ? 17 : 12} fill={nodeColors[node.entityType] || "#a8b3c7"} /><circle cx={node.x} cy={node.y} r={node.id === expanded ? 24 : 18} fill="none" stroke={nodeColors[node.entityType] || "#a8b3c7"} opacity=".24" />
        </g>)}
      </svg>
      <div className="graph-legend">{types.map(type => <span key={type}><i style={{ backgroundColor: nodeColors[type] || "#a8b3c7" }} />{type}</span>)}</div>
      <div className="graph-detail">{active ? <><span className="type-chip">{active.entityType}</span><strong>{active.label}</strong><code>{active.value}</code><p>{active.confidence}% confidence • click the node again to collapse.</p>{active.evidence ? <div className="graph-evidence"><span className={`quality-${active.evidence.evidenceQuality}`}>{active.evidence.evidenceQuality}</span><span className={active.evidence.leadStatus === "review" ? "graph-review" : "graph-verified"}>{active.evidence.leadStatus}</span><p>{active.evidence.sourceCount} declared source reference(s) · {active.evidence.findingCount} linked finding(s)</p>{active.evidence.collectedAt ? <p>Freshness: {new Date(active.evidence.collectedAt).toLocaleString()}</p> : null}{active.evidence.limitations.length ? <p className="graph-limitations">Limitations: {active.evidence.limitations.join(" ")}</p> : null}</div> : <p className="graph-limitations">No linked provenance was preserved for this historic entity.</p>}</> : <p>Select a node to inspect evidence quality, review status, sources, freshness, and limitations. Filters reduce the displayed surface without changing stored evidence.</p>}</div>
    </div>}
  </section>;
}
