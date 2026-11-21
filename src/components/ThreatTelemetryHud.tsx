import React, { useMemo } from 'react';
import { ForensicEvent } from '../types/forensics';

interface ThreatTelemetryHudProps {
  events: ForensicEvent[];
  severityFilter: string;
  tacticFilter: string;
  onSelectSeverity: (sev: string) => void;
  onSelectTactic: (tactic: string) => void;
}

const RADAR_AXES = [
  { tactic: 'Lateral Movement', shortLabel: 'Lateral', angleDeg: -90 },
  { tactic: 'Execution', shortLabel: 'Execution', angleDeg: -30 },
  { tactic: 'Defense Evasion', shortLabel: 'Evasion', angleDeg: 30 },
  { tactic: 'Credential Access', shortLabel: 'Creds', angleDeg: 90 },
  { tactic: 'Impact', shortLabel: 'Impact', angleDeg: 150 },
  { tactic: 'Persistence', shortLabel: 'Persist', angleDeg: 210 },
] as const;

const SEVERITY_RANK: Record<string, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityStrokeColor(sev: string): string {
  if (sev === 'critical') return '#E11D48';
  if (sev === 'high') return '#D97706';
  if (sev === 'medium') return '#0284C7';
  return '#4F46E5';
}

export const ThreatTelemetryHud: React.FC<ThreatTelemetryHudProps> = ({
  events,
  severityFilter,
  tacticFilter,
  onSelectSeverity,
  onSelectTactic,
}) => {
  const stats = useMemo(() => {
    const flagged = events.filter((e) => e.sigma_flagged);
    const critical = flagged.filter((e) => e.sigma_severity === 'critical').length;
    const high = flagged.filter((e) => e.sigma_severity === 'high').length;
    const medium = flagged.filter((e) => e.sigma_severity === 'medium').length;
    return {
      total: events.length,
      flagged: flagged.length,
      critical,
      highMed: high + medium,
    };
  }, [events]);

  const radarPlot = useMemo(() => {
    const byTactic = new Map<string, { count: number; maxSeverity: string }>();
    for (const evt of events) {
      for (const alert of evt.sigma_alerts) {
        const curr = byTactic.get(alert.mitre_tactic) || { count: 0, maxSeverity: 'none' };
        curr.count += 1;
        if (SEVERITY_RANK[alert.severity] > SEVERITY_RANK[curr.maxSeverity]) {
          curr.maxSeverity = alert.severity;
        }
        byTactic.set(alert.mitre_tactic, curr);
      }
    }

    return RADAR_AXES.map((axis) => {
      const data = byTactic.get(axis.tactic) || { count: 0, maxSeverity: 'none' };
      const rad = (axis.angleDeg * Math.PI) / 180;
      const dist =
        data.count === 0
          ? 0
          : data.maxSeverity === 'critical'
            ? 74
            : data.maxSeverity === 'high'
              ? 56
              : 38;
      const x = 110 + dist * Math.cos(rad);
      const y = 110 + dist * Math.sin(rad);
      const labelX = 110 + 95 * Math.cos(rad);
      const labelY = 110 + 95 * Math.sin(rad);
      const axisEndX = 110 + 82 * Math.cos(rad);
      const axisEndY = 110 + 82 * Math.sin(rad);
      return {
        ...axis,
        count: data.count,
        maxSeverity: data.maxSeverity,
        x,
        y,
        labelX,
        labelY,
        axisEndX,
        axisEndY,
        color: severityStrokeColor(data.maxSeverity),
      };
    });
  }, [events]);

  const gaugeCards = useMemo(() => {
    const totalBase = Math.max(stats.total, 1);
    return [
      {
        id: 'total',
        label: 'Indexed Events',
        value: stats.total,
        ratio: stats.total > 0 ? 1 : 0,
        color: '#4F46E5',
        subtext: stats.total > 0 ? 'Active telemetry' : 'Awaiting logs',
        filterValue: '',
        clickable: false,
      },
      {
        id: 'flagged',
        label: 'Sigma Flagged',
        value: stats.flagged,
        ratio: stats.total > 0 ? stats.flagged / totalBase : 0,
        color: '#0284C7',
        subtext:
          stats.total > 0 ? `${Math.round((stats.flagged / totalBase) * 100)}% alert rate` : '0% alert rate',
        filterValue: '',
        clickable: true,
      },
      {
        id: 'critical',
        label: 'Critical Alerts',
        value: stats.critical,
        ratio: stats.total > 0 ? stats.critical / totalBase : 0,
        color: '#E11D48',
        subtext: 'Click to filter',
        filterValue: 'critical',
        clickable: true,
      },
      {
        id: 'high',
        label: 'High / Medium',
        value: stats.highMed,
        ratio: stats.total > 0 ? stats.highMed / totalBase : 0,
        color: '#D97706',
        subtext: 'Click to filter',
        filterValue: 'high',
        clickable: true,
      },
    ];
  }, [stats]);

  const radius = 23;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
      {/* Left: Live Animated MITRE Threat Radar */}
      <div className="xl:col-span-5 lab-panel rounded-xl p-4 flex flex-col sm:flex-row items-center gap-4 shadow-xs">
        <div className="relative w-[176px] h-[176px] shrink-0">
          <svg viewBox="0 0 220 220" className="w-full h-full overflow-visible" aria-label="MITRE ATT&CK Threat Radar">
            <defs>
              <radialGradient id="labRadarSweepGrad" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#0284C7" stopOpacity="0.02" />
                <stop offset="100%" stopColor="#0284C7" stopOpacity="0.22" />
              </radialGradient>
            </defs>

            {/* Concentric range rings */}
            <circle cx="110" cy="110" r="82" fill="#F8FAFC" stroke="rgba(2,132,199,0.22)" strokeWidth="1" />
            <circle cx="110" cy="110" r="56" fill="none" stroke="rgba(2,132,199,0.16)" strokeWidth="1" strokeDasharray="3 3" />
            <circle cx="110" cy="110" r="30" fill="none" stroke="rgba(2,132,199,0.16)" strokeWidth="1" />

            {/* 6 Tactical Axes */}
            {radarPlot.map((axis) => (
              <line
                key={axis.tactic}
                x1="110"
                y1="110"
                x2={axis.axisEndX}
                y2={axis.axisEndY}
                stroke="rgba(100,116,139,0.25)"
                strokeWidth="1"
              />
            ))}

            {/* Animated Sweep Sector */}
            <g className="radar-sweep-arm">
              <path
                d="M 110 110 L 110 28 A 82 82 0 0 1 181 69 Z"
                fill="url(#labRadarSweepGrad)"
              />
              <line x1="110" y1="110" x2="110" y2="28" stroke="#0284C7" strokeWidth="1.5" strokeOpacity="0.72" />
            </g>

            {/* Threat Polygon Connecting Active Tactics */}
            {radarPlot.filter((p) => p.count > 0).length >= 3 && (
              <polygon
                points={radarPlot
                  .filter((p) => p.count > 0)
                  .map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`)
                  .join(' ')}
                fill="rgba(79, 70, 229, 0.12)"
                stroke="rgba(79, 70, 229, 0.65)"
                strokeWidth="1.3"
              />
            )}

            {/* Plotted Blips & Tactic Axis Labels */}
            {radarPlot.map((axis) => {
              const isSelected = tacticFilter === axis.tactic;
              return (
                <g
                  key={axis.tactic}
                  className="cursor-pointer"
                  onClick={() => onSelectTactic(isSelected ? '' : axis.tactic)}
                >
                  <text
                    x={axis.labelX}
                    y={axis.labelY}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={isSelected ? '#0284C7' : axis.count > 0 ? '#0F172A' : '#64748B'}
                    fontSize="9.5"
                    fontWeight={isSelected || axis.count > 0 ? '600' : '500'}
                    fontFamily="JetBrains Mono, monospace"
                  >
                    {axis.shortLabel}
                  </text>
                  {axis.count > 0 && (
                    <>
                      <circle
                        cx={axis.x}
                        cy={axis.y}
                        r={isSelected ? 8.5 : 6.5}
                        fill={axis.color}
                        fillOpacity="0.2"
                      />
                      <circle
                        cx={axis.x}
                        cy={axis.y}
                        r={isSelected ? 4.5 : 3.5}
                        fill={axis.color}
                        stroke="#FFFFFF"
                        strokeWidth="1.4"
                      />
                    </>
                  )}
                </g>
              );
            })}

            <circle cx="110" cy="110" r="2.8" fill="#0284C7" />
          </svg>
        </div>

        <div className="flex-1 w-full min-w-0 space-y-2">
          <div>
            <div className="text-xs font-semibold text-slate-900 font-display">Threat Radar</div>
            <div className="text-[11px] text-slate-500">
              {stats.flagged > 0 ? 'Click a tactic to filter alerts' : 'Idle sweep awaiting logs'}
            </div>
          </div>

          <div className="space-y-1">
            {radarPlot.map((axis) => {
              const isActive = tacticFilter === axis.tactic;
              return (
                <button
                  key={axis.tactic}
                  type="button"
                  onClick={() => onSelectTactic(isActive ? '' : axis.tactic)}
                  className={`w-full flex items-center justify-between gap-2 px-2 py-1 rounded text-[11px] transition-colors ${
                    isActive
                      ? 'bg-sky-50 text-sky-800 border border-sky-300 font-semibold'
                      : 'text-slate-700 hover:bg-slate-100 border border-transparent'
                  }`}
                >
                  <span className="truncate">{axis.tactic}</span>
                  <span
                    className={`font-mono tabular-nums font-semibold ${
                      axis.count > 0 ? 'text-sky-700' : 'text-slate-400'
                    }`}
                  >
                    {axis.count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right: 4 Radial Severity Arc Gauges */}
      <div className="xl:col-span-7 grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-2 gap-3.5">
        {gaugeCards.map((card) => {
          const isSelected =
            card.clickable &&
            ((card.id === 'critical' && severityFilter === 'critical') ||
              (card.id === 'high' && severityFilter === 'high'));
          const dashOffset = circumference * (1 - Math.min(1, Math.max(0, card.ratio)));

          return (
            <button
              key={card.id}
              type="button"
              disabled={!card.clickable}
              onClick={() => {
                if (!card.clickable) return;
                if (card.id === 'flagged') {
                  onSelectSeverity('');
                  onSelectTactic('');
                } else {
                  onSelectSeverity(severityFilter === card.filterValue ? '' : card.filterValue);
                }
              }}
              className={`lab-panel rounded-xl p-4 flex items-center gap-3.5 text-left transition-colors shadow-xs ${
                isSelected
                  ? 'border-sky-500 bg-sky-50/90'
                  : card.clickable
                    ? 'hover:border-sky-400 cursor-pointer'
                    : 'cursor-default'
              }`}
            >
              <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
                <svg viewBox="0 0 56 56" className="w-full h-full -rotate-90">
                  <circle
                    cx="28"
                    cy="28"
                    r={radius}
                    fill="none"
                    stroke="#E2E8F0"
                    strokeWidth="4.5"
                  />
                  <circle
                    cx="28"
                    cy="28"
                    r={radius}
                    fill="none"
                    stroke={card.color}
                    strokeWidth="4.5"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={dashOffset}
                    style={{ transition: 'stroke-dashoffset 450ms cubic-bezier(0.16, 1, 0.3, 1)' }}
                  />
                </svg>
                <span className="absolute font-mono tabular-nums text-sm font-bold text-slate-900">
                  {card.value}
                </span>
              </div>

              <div className="min-w-0">
                <div className="text-xs font-semibold text-slate-900 truncate">{card.label}</div>
                <div className="text-[11px] text-slate-500 truncate mt-0.5">{card.subtext}</div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
