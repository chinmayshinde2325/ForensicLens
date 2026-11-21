export interface SigmaAlert {
  rule_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitre_tactic: string;
  mitre_technique: string;
  description: string;
}

export interface ForensicEvent {
  doc_id: string;
  timestamp: string;
  channel: string;
  event_id: string;
  host: string;
  user: string;
  process_name: string;
  parent_process?: string;
  command_line: string;
  target_image?: string;
  granted_access?: string;
  logon_type?: string;
  source_ip?: string;
  message: string;
  sigma_flagged: boolean;
  sigma_severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  sigma_alerts: SigmaAlert[];
}

export type CopilotMode = 'investigate' | 'hunt' | 'remediate' | 'sigma_rule';

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  mode?: CopilotMode;
  citations?: ForensicEvent[];
  dslQuery?: Record<string, unknown>;
  mitreTechniques?: string[];
  followUps?: string[];
  isError?: boolean;
}

export interface SavedSession {
  id: string;
  filename: string;
  savedAt: string;
  totalEvents: number;
  flaggedEvents: number;
  events: ForensicEvent[];
  messages: CopilotMessage[];
}

export function formatTs(ts: string): string {
  return ts.replace('T', ' ').replace(/\.\d+Z?$/, 'Z').slice(0, 20);
}

export function severityMeta(sev: string) {
  const s = (sev || 'none').toLowerCase();
  if (s === 'critical') {
    return {
      bg: 'bg-rose-50',
      border: 'border-rose-200',
      text: 'text-rose-700',
      stroke: '#E11D48',
      label: 'CRITICAL',
    };
  }
  if (s === 'high') {
    return {
      bg: 'bg-amber-50',
      border: 'border-amber-200',
      text: 'text-amber-700',
      stroke: '#D97706',
      label: 'HIGH',
    };
  }
  if (s === 'medium') {
    return {
      bg: 'bg-sky-50',
      border: 'border-sky-200',
      text: 'text-sky-700',
      stroke: '#0284C7',
      label: 'MEDIUM',
    };
  }
  return {
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    text: 'text-emerald-700',
    stroke: '#059669',
    label: 'INFO',
  };
}
