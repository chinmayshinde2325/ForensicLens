import React, { useMemo, useState } from 'react';
import { ForensicEvent, formatTs, severityMeta } from '../types/forensics';

interface AttackGraphPanelProps {
  events: ForensicEvent[];
  onSelectDoc: (docId: string) => void;
}

type NodeColumn = 0 | 1 | 2 | 3 | 4;

interface GraphNode {
  id: string;
  label: string;
  kind: 'Source IP' | 'Host' | 'User' | 'Process' | 'Target';
  col: NodeColumn;
  severity: string;
  docIds: string[];
  x: number;
  y: number;
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  severity: string;
  docId: string;
}

const SEV_RANK: Record<string, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const COL_TITLES = ['Source IP', 'Host', 'User', 'Process', 'Target'] as const;
const COL_X = [78, 232, 386, 540, 694] as const;

function sevStroke(sev: string): string {
  if (sev === 'critical') return '#E11D48';
  if (sev === 'high') return '#D97706';
  if (sev === 'medium') return '#0284C7';
  return '#4F46E5';
}

function shortProcessName(raw: string): string {
  const cleaned = raw.split(/[\\/]/).pop() || raw;
  return cleaned.length > 18 ? `${cleaned.slice(0, 16)}..` : cleaned;
}

export const AttackGraphPanel: React.FC<AttackGraphPanelProps> = ({ events, onSelectDoc }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const orderedTimeline = useMemo(
    () => [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
    [events],
  );

  const { nodes, edges, svgHeight } = useMemo(() => {
    const nodeMap = new Map<string, Omit<GraphNode, 'x' | 'y'>>();
    const edgeMap = new Map<string, GraphEdge>();

    const upsertNode = (
      id: string,
      label: string,
      kind: GraphNode['kind'],
      col: NodeColumn,
      severity: string,
      docId: string,
    ) => {
      const existing = nodeMap.get(id);
      if (existing) {
        if (!existing.docIds.includes(docId)) existing.docIds.push(docId);
        if (SEV_RANK[severity] > SEV_RANK[existing.severity]) {
          existing.severity = severity;
        }
      } else {
        nodeMap.set(id, { id, label, kind, col, severity, docIds: [docId] });
      }
    };

    const addEdge = (from: string, to: string, severity: string, docId: string) => {
      const key = `${from}__${to}`;
      const existing = edgeMap.get(key);
      if (existing) {
        if (SEV_RANK[severity] > SEV_RANK[existing.severity]) {
          existing.severity = severity;
        }
      } else {
        edgeMap.set(key, { id: key, from, to, severity, docId });
      }
    };

    for (const evt of orderedTimeline.slice(0, 40)) {
      const sev = evt.sigma_severity || 'none';
      const hostId = `host:${evt.host || 'UNKNOWN'}`;
      upsertNode(hostId, evt.host || 'UNKNOWN', 'Host', 1, sev, evt.doc_id);

      const userId = `user:${evt.user || 'SYSTEM'}`;
      upsertNode(userId, evt.user || 'SYSTEM', 'User', 2, sev, evt.doc_id);
      addEdge(hostId, userId, sev, evt.doc_id);

      if (evt.source_ip) {
        const ipId = `ip:${evt.source_ip}`;
        upsertNode(ipId, evt.source_ip, 'Source IP', 0, sev, evt.doc_id);
        addEdge(ipId, hostId, sev, evt.doc_id);
      }

      const procRaw = evt.process_name || `Event ${evt.event_id}`;
      const procId = `proc:${procRaw}`;
      upsertNode(procId, shortProcessName(procRaw), 'Process', 3, sev, evt.doc_id);
      addEdge(userId, procId, sev, evt.doc_id);

      const targetRaw =
        evt.target_image ||
        (evt.command_line.toLowerCase().includes('vssadmin')
          ? 'Shadow Copies'
          : evt.command_line.toLowerCase().includes('mppreference')
            ? 'Windows Defender'
            : evt.command_line.toLowerCase().includes('-enc')
              ? 'Encoded Script'
              : '');
      if (targetRaw) {
        const tgtId = `tgt:${targetRaw}`;
        upsertNode(tgtId, shortProcessName(targetRaw), 'Target', 4, sev, evt.doc_id);
        addEdge(procId, tgtId, sev, evt.doc_id);
      }
    }

    const colBuckets: Omit<GraphNode, 'x' | 'y'>[][] = [[], [], [], [], []];
    for (const n of nodeMap.values()) {
      colBuckets[n.col].push(n);
    }
    const maxRows = Math.max(1, ...colBuckets.map((b) => b.length));
    const computedHeight = Math.max(250, 74 + maxRows * 56);

    const positionedNodes: GraphNode[] = [];
    colBuckets.forEach((bucket, colIdx) => {
      const spacing = (computedHeight - 62) / (bucket.length + 1);
      bucket.forEach((item, idx) => {
        positionedNodes.push({
          ...item,
          x: COL_X[colIdx],
          y: 44 + spacing * (idx + 1),
        });
      });
    });

    return {
      nodes: positionedNodes,
      edges: Array.from(edgeMap.values()),
      svgHeight: computedHeight,
    };
  }, [orderedTimeline]);

  const activeNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId],
  );

  const connectedDocEvents = useMemo(() => {
    if (!activeNode) return [];
    const setIds = new Set(activeNode.docIds);
    return orderedTimeline.filter((e) => setIds.has(e.doc_id));
  }, [activeNode, orderedTimeline]);

  if (events.length === 0) {
    return (
      <div className="lab-panel rounded-xl py-16 px-6 text-center space-y-2 shadow-xs">
        <p className="text-sm font-semibold text-slate-900 font-display">No Attack Telemetry Plotted</p>
        <p className="text-xs text-slate-500">
          Upload a Windows <span className="font-mono text-sky-700 font-medium">.jsonl</span> or{' '}
          <span className="font-mono text-sky-700 font-medium">.evtx</span> log file to construct the attack timeline and entity graph.
        </p>
      </div>
    );
  }

  const nodeLookup = new Map(nodes.map((n) => [n.id, n]));

  return (
    <div className="space-y-4">
      {/* Interactive Chronological Attack Timeline */}
      <div className="lab-panel rounded-xl p-4 space-y-3 shadow-xs">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold text-slate-900 font-display">
              Chronological Attack Timeline
            </h3>
            <p className="text-[11px] text-slate-500">
              Select any sequence step to inspect full forensic evidence
            </p>
          </div>
          <span className="text-[11px] font-mono tabular-nums text-sky-700 font-semibold">
            {orderedTimeline.length} events
          </span>
        </div>

        <div className="flex items-stretch gap-2.5 overflow-x-auto pb-1">
          {orderedTimeline.slice(0, 24).map((evt, idx) => {
            const style = severityMeta(evt.sigma_severity);
            return (
              <button
                key={evt.doc_id}
                type="button"
                onClick={() => onSelectDoc(evt.doc_id)}
                className="min-w-[188px] max-w-[210px] shrink-0 text-left rounded-lg bg-slate-50 hover:bg-sky-50 border border-slate-200 hover:border-sky-400 p-3 transition-colors space-y-1"
              >
                <div className="flex items-center justify-between gap-2 text-[10px] font-mono tabular-nums">
                  <span className="text-indigo-600 font-semibold">T{idx + 1}</span>
                  <span className={style.text}>{style.label}</span>
                </div>
                <div className="text-[11px] font-semibold text-slate-900 truncate">
                  {evt.sigma_alerts[0]?.title || `Event ${evt.event_id}`}
                </div>
                <div className="text-[10px] font-mono tabular-nums text-slate-500 truncate">
                  {formatTs(evt.timestamp)} · {shortProcessName(evt.process_name || evt.host)}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive SVG Entity Relationship Graph */}
      <div className="lab-panel rounded-xl p-4 space-y-3 shadow-xs">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold text-slate-900 font-display">
              Entity &amp; Lateral Movement Graph
            </h3>
            <p className="text-[11px] text-slate-500">
              Click any node to isolate its attack path and linked events
            </p>
          </div>
          {selectedNodeId && (
            <button
              type="button"
              onClick={() => setSelectedNodeId(null)}
              className="px-2.5 py-1 text-[11px] font-medium text-sky-800 bg-sky-50 hover:bg-sky-100 border border-sky-300 rounded-md whitespace-nowrap"
            >
              Reset Selection
            </button>
          )}
        </div>

        <div className="w-full overflow-x-auto rounded-lg bg-slate-50/80 border border-slate-200">
          <svg
            viewBox={`0 0 772 ${svgHeight}`}
            className="w-full min-w-[680px]"
            style={{ height: `${svgHeight}px` }}
            aria-label="Interactive Attack Entity Graph"
          >
            {/* Column Headers */}
            {COL_TITLES.map((title, i) => (
              <text
                key={title}
                x={COL_X[i]}
                y={22}
                textAnchor="middle"
                fill="#475569"
                fontSize="10"
                fontWeight="600"
                fontFamily="JetBrains Mono, monospace"
              >
                {title}
              </text>
            ))}

            {/* Directed Bezier Edges */}
            {edges.map((edge) => {
              const fromNode = nodeLookup.get(edge.from);
              const toNode = nodeLookup.get(edge.to);
              if (!fromNode || !toNode) return null;
              const isHighlighted =
                !selectedNodeId || edge.from === selectedNodeId || edge.to === selectedNodeId;
              const midX = (fromNode.x + toNode.x) / 2;
              const pathD = `M ${fromNode.x + 56} ${fromNode.y} C ${midX} ${fromNode.y}, ${midX} ${toNode.y}, ${toNode.x - 56} ${toNode.y}`;
              return (
                <path
                  key={edge.id}
                  d={pathD}
                  fill="none"
                  stroke={sevStroke(edge.severity)}
                  strokeWidth={isHighlighted ? 2 : 1.1}
                  strokeOpacity={isHighlighted ? 0.78 : 0.16}
                />
              );
            })}

            {/* Entity Nodes */}
            {nodes.map((node) => {
              const isSelected = selectedNodeId === node.id;
              const isConnected =
                !selectedNodeId ||
                isSelected ||
                edges.some(
                  (e) =>
                    (e.from === selectedNodeId && e.to === node.id) ||
                    (e.to === selectedNodeId && e.from === node.id),
                );
              const stroke = isSelected ? '#0284C7' : sevStroke(node.severity);
              return (
                <g
                  key={node.id}
                  className="cursor-pointer"
                  opacity={isConnected ? 1 : 0.3}
                  onClick={() => setSelectedNodeId(isSelected ? null : node.id)}
                >
                  <rect
                    x={node.x - 56}
                    y={node.y - 17}
                    width={112}
                    height={34}
                    rx={7}
                    fill={isSelected ? '#E0F2FE' : '#FFFFFF'}
                    stroke={stroke}
                    strokeWidth={isSelected ? 2 : 1.3}
                  />
                  <text
                    x={node.x}
                    y={node.y + 1}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="#0F172A"
                    fontSize="10"
                    fontWeight="600"
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {node.label.length > 15 ? `${node.label.slice(0, 14)}…` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Linked Events Drawer for Selected Graph Node */}
        {activeNode && connectedDocEvents.length > 0 && (
          <div className="pt-2 border-t border-slate-200 space-y-2">
            <div className="text-xs font-semibold text-sky-800">
              {activeNode.kind}: {activeNode.label} ({connectedDocEvents.length} linked events)
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {connectedDocEvents.map((evt) => {
                const style = severityMeta(evt.sigma_severity);
                return (
                  <button
                    key={evt.doc_id}
                    type="button"
                    onClick={() => onSelectDoc(evt.doc_id)}
                    className="text-left px-3 py-2 rounded-lg bg-slate-50 hover:bg-sky-50 border border-slate-200 hover:border-sky-300 transition-colors space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2 text-[10px] font-mono">
                      <span className={style.text}>{style.label}</span>
                      <span className="text-slate-500 tabular-nums">{formatTs(evt.timestamp)}</span>
                    </div>
                    <div className="text-xs font-medium text-slate-900 truncate">
                      {evt.sigma_alerts[0]?.title || evt.message}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
