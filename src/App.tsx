import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Check,
  Copy,
  Download,
  FileUp,
  History,
  ListFilter,
  Network,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  Trash2,
  X,
} from 'lucide-react';
import { AttackGraphPanel } from './components/AttackGraphPanel';
import { ThreatTelemetryHud } from './components/ThreatTelemetryHud';
import {
  CopilotMessage,
  CopilotMode,
  ForensicEvent,
  formatTs,
  SavedSession,
  severityMeta,
  SigmaAlert,
} from './types/forensics';

const SIGMA_RULES_CATALOG: SigmaAlert[] = [
  {
    rule_id: 'fl-sigma-001',
    title: 'Ransomware Shadow Copy & Backup Deletion',
    severity: 'critical',
    mitre_tactic: 'Impact',
    mitre_technique: 'T1490',
    description:
      'Detects vssadmin, wmic shadowcopy, bcdedit recovery disabling, or wbadmin catalog deletion.',
  },
  {
    rule_id: 'fl-sigma-002',
    title: 'LSASS Memory Dump / Credential Access',
    severity: 'critical',
    mitre_tactic: 'Credential Access',
    mitre_technique: 'T1003.001',
    description:
      'Detects Sysmon Event ID 10 access to lsass.exe or comsvcs.dll MiniDump / procdump / mimikatz execution.',
  },
  {
    rule_id: 'fl-sigma-003',
    title: 'Encoded or Hidden PowerShell Execution',
    severity: 'high',
    mitre_tactic: 'Execution',
    mitre_technique: 'T1059.001',
    description:
      'Detects powershell.exe or pwsh.exe launched with -EncodedCommand, -enc, -W Hidden, or FromBase64String.',
  },
  {
    rule_id: 'fl-sigma-004',
    title: 'RDP Lateral Movement & Session Hijack',
    severity: 'high',
    mitre_tactic: 'Lateral Movement',
    mitre_technique: 'T1021.001',
    description:
      'Detects RemoteInteractive (LogonType 10) Security 4624 logons, 4778/4779 reconnects, or mstsc.exe / tscon.exe.',
  },
  {
    rule_id: 'fl-sigma-005',
    title: 'Windows Defender / Security Service Tampering',
    severity: 'critical',
    mitre_tactic: 'Defense Evasion',
    mitre_technique: 'T1562.001',
    description:
      'Detects attempts to disable Windows Defender real-time monitoring or stop security services.',
  },
  {
    rule_id: 'fl-sigma-006',
    title: 'Scheduled Task Persistence Creation',
    severity: 'medium',
    mitre_tactic: 'Persistence',
    mitre_technique: 'T1053.005',
    description:
      'Detects scheduled task creation via schtasks.exe /create or PowerShell Register-ScheduledTask.',
  },
];

function decodePowerShellBase64(commandLine: string): string | null {
  const match = commandLine.match(/(?:-EncodedCommand|-enc|-ec|-e)\s+([A-Za-z0-9+/=]{16,})/i);
  if (!match) return null;
  try {
    const binary = atob(match[1]);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoded = new TextDecoder('utf-16le').decode(bytes).replace(/\0/g, '').trim();
    return decoded || null;
  } catch {
    return null;
  }
}

function evaluateSigmaRules(
  evt: Omit<ForensicEvent, 'sigma_flagged' | 'sigma_severity' | 'sigma_alerts'>,
): ForensicEvent {
  const cmd = (evt.command_line || '').toLowerCase();
  const proc = (evt.process_name || '').toLowerCase();
  const target = (evt.target_image || '').toLowerCase();
  const access = (evt.granted_access || '').toLowerCase();
  const alerts: SigmaAlert[] = [];

  if (
    (cmd.includes('vssadmin') && cmd.includes('delete')) ||
    (cmd.includes('shadowcopy') && cmd.includes('delete')) ||
    (cmd.includes('bcdedit') && cmd.includes('recoveryenabled')) ||
    (cmd.includes('wbadmin') && cmd.includes('delete') && cmd.includes('catalog'))
  ) {
    alerts.push(SIGMA_RULES_CATALOG[0]);
  }

  if (
    (evt.event_id === '10' &&
      target.endsWith('lsass.exe') &&
      ['0x1010', '0x1410', '0x143a', '0x1fffff'].includes(access)) ||
    cmd.includes('comsvcs.dll') ||
    cmd.includes('minidump') ||
    cmd.includes('procdump') ||
    cmd.includes('mimikatz')
  ) {
    alerts.push(SIGMA_RULES_CATALOG[1]);
  }

  if (
    (proc.includes('powershell') || proc.includes('pwsh') || cmd.includes('powershell')) &&
    (cmd.includes('-encodedcommand') ||
      cmd.includes('-enc ') ||
      cmd.includes('frombase64string') ||
      cmd.includes('-w hidden'))
  ) {
    alerts.push(SIGMA_RULES_CATALOG[2]);
  }

  if (
    (evt.event_id === '4624' && evt.logon_type === '10') ||
    evt.event_id === '4778' ||
    evt.event_id === '4779' ||
    proc.endsWith('mstsc.exe') ||
    cmd.includes('mstsc') ||
    cmd.includes('tscon')
  ) {
    alerts.push(SIGMA_RULES_CATALOG[3]);
  }

  if (
    cmd.includes('disablerealtimemonitoring') ||
    cmd.includes('disablebehaviormonitoring') ||
    cmd.includes('add-mppreference') ||
    cmd.includes('windefend')
  ) {
    alerts.push(SIGMA_RULES_CATALOG[4]);
  }

  if ((cmd.includes('schtasks') && cmd.includes('create')) || cmd.includes('register-scheduledtask')) {
    alerts.push(SIGMA_RULES_CATALOG[5]);
  }

  const rank: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  let topSev: ForensicEvent['sigma_severity'] = 'none';
  for (const a of alerts) {
    if (rank[a.severity] > rank[topSev]) {
      topSev = a.severity;
    }
  }

  return {
    ...evt,
    sigma_flagged: alerts.length > 0,
    sigma_severity: topSev,
    sigma_alerts: alerts,
  };
}

const HISTORY_STORAGE_KEY = 'forensiclens_history_v1';

function loadSavedHistory(): SavedSession[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

const WELCOME_MESSAGE: CopilotMessage = {
  id: 'welcome',
  role: 'assistant',
  content:
    'ForensicLens AI Copilot online. Drop a `.jsonl` log file to light up the Threat Radar and Attack Graph, then choose a mode above to reconstruct timelines, hunt lateral movement, generate containment commands, or author Sigma YAML rules.',
  followUps: [
    'Summarize attack timeline and root cause',
    'Decode any Base64 PowerShell payloads',
    'Generate containment playbook and Sigma rule',
  ],
};

const COPILOT_MODES: { id: CopilotMode; label: string; placeholder: string }[] = [
  {
    id: 'investigate',
    label: 'Investigate',
    placeholder: 'Ask about timeline, root cause, decoded PowerShell, or LSASS access...',
  },
  {
    id: 'hunt',
    label: 'Threat Hunt',
    placeholder: 'Hunt lateral movement, suspicious parent-child processes, or external IPs...',
  },
  {
    id: 'remediate',
    label: 'Contain',
    placeholder: 'Request immediate host isolation, credential reset, and eradication commands...',
  },
  {
    id: 'sigma_rule',
    label: 'Sigma Rule',
    placeholder: 'Ask to generate a Sigma YAML + OpenSearch DSL rule for an observed TTP...',
  },
];

export default function App() {
  const [events, setEvents] = useState<ForensicEvent[]>([]);
  const [activeFileName, setActiveFileName] = useState<string>('');
  const [history, setHistory] = useState<SavedSession[]>(() => loadSavedHistory());
  const [view, setView] = useState<'triage' | 'all' | 'graph' | 'rules' | 'history'>('triage');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [tacticFilter, setTacticFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null);
  const [uploadNotice, setUploadNotice] = useState<string>('');
  const [chatInput, setChatInput] = useState<string>('');
  const [copilotMode, setCopilotMode] = useState<CopilotMode>('investigate');
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<CopilotMessage[]>([WELCOME_MESSAGE]);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const chatScrollRef = useRef<HTMLDivElement | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [messages, isStreaming]);

  const persistHistory = (next: SavedSession[]) => {
    setHistory(next);
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(next.slice(0, 20)));
    } catch {}
  };

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (view === 'triage' && !evt.sigma_flagged) return false;
      if (severityFilter && evt.sigma_severity !== severityFilter) return false;
      if (tacticFilter && !evt.sigma_alerts.some((a) => a.mitre_tactic === tacticFilter)) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const hay = `${evt.host} ${evt.user} ${evt.event_id} ${evt.command_line} ${evt.message}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [events, view, severityFilter, tacticFilter, searchQuery]);

  const selectedEvent = useMemo(
    () => events.find((e) => e.doc_id === selectedDocId) ?? null,
    [events, selectedDocId],
  );

  const decodedPowerShell = useMemo(
    () => (selectedEvent ? decodePowerShellBase64(selectedEvent.command_line) : null),
    [selectedEvent],
  );

  const handleClearChatAndResetPage = () => {
    abortControllerRef.current?.abort();
    setIsStreaming(false);
    const hasSessionData = events.length > 0 || messages.length > 1;
    if (hasSessionData) {
      const snapshot: SavedSession = {
        id: `sess_${Date.now()}`,
        filename: activeFileName || 'Investigation Session',
        savedAt: new Date().toISOString(),
        totalEvents: events.length,
        flaggedEvents: events.filter((e) => e.sigma_flagged).length,
        events,
        messages,
      };
      persistHistory([snapshot, ...history]);
    }

    setEvents([]);
    setActiveFileName('');
    setSeverityFilter('');
    setTacticFilter('');
    setSearchQuery('');
    setSelectedDocId(null);
    setChatInput('');
    setMessages([WELCOME_MESSAGE]);
    setUploadNotice(hasSessionData ? 'Session saved to History · Fresh workspace ready' : '');
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (view === 'history') setView('triage');
  };

  const handleClearHistory = () => {
    abortControllerRef.current?.abort();
    setIsStreaming(false);
    persistHistory([]);
    setEvents([]);
    setActiveFileName('');
    setSeverityFilter('');
    setTacticFilter('');
    setSearchQuery('');
    setSelectedDocId(null);
    setChatInput('');
    setMessages([WELCOME_MESSAGE]);
    setUploadNotice('All saved history cleared');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleRestoreSession = (session: SavedSession) => {
    setEvents(session.events);
    setActiveFileName(session.filename);
    setMessages(session.messages.length > 0 ? session.messages : [WELCOME_MESSAGE]);
    setSeverityFilter('');
    setTacticFilter('');
    setSearchQuery('');
    setSelectedDocId(null);
    setUploadNotice(`Restored ${session.filename} · ${session.totalEvents} events`);
    setView('triage');
  };

  const handleDeleteHistoryItem = (id: string) => {
    persistHistory(history.filter((item) => item.id !== id));
  };

  const handleExportReport = () => {
    const flagged = events.filter((e) => e.sigma_flagged);
    const payload = {
      case_id: 'forensic-case-001',
      exported_at: new Date().toISOString(),
      total_events: events.length,
      flagged_events: flagged.length,
      events: flagged,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'forensiclens-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleFileImport = async (file: File | undefined) => {
    if (!file) return;
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext === 'evtx') {
      setUploadNotice(`Selected ${file.name} (run FastAPI on Windows for binary .evtx parsing)`);
      return;
    }
    try {
      const text = await file.text();
      const lines = text.trim().startsWith('[')
        ? (JSON.parse(text) as Record<string, unknown>[])
        : text
            .split(/\r?\n/)
            .filter((l) => l.trim().length > 0)
            .map((l) => JSON.parse(l) as Record<string, unknown>);

      const parsed: ForensicEvent[] = lines.map((raw, idx) =>
        evaluateSigmaRules({
          doc_id: `imp_${Date.now().toString(16)}_${idx}`,
          timestamp: String(raw.timestamp || new Date().toISOString()),
          channel: String(raw.channel || 'Security'),
          event_id: String(raw.event_id || '0'),
          host: String(raw.host || 'WIN-WORKSTATION'),
          user: String(raw.user || 'SYSTEM'),
          process_name: String(raw.process_name || ''),
          parent_process: raw.parent_process ? String(raw.parent_process) : undefined,
          command_line: String(raw.command_line || ''),
          target_image: raw.target_image ? String(raw.target_image) : undefined,
          granted_access: raw.granted_access ? String(raw.granted_access) : undefined,
          logon_type: raw.logon_type ? String(raw.logon_type) : undefined,
          source_ip: raw.source_ip ? String(raw.source_ip) : undefined,
          message: String(raw.message || raw.command_line || 'Imported event'),
        }),
      );

      setEvents((prev) => [...parsed, ...prev]);
      setActiveFileName(file.name);
      const newlyFlagged = parsed.filter((p) => p.sigma_flagged).length;
      setUploadNotice(`Indexed ${file.name} · ${parsed.length} events · ${newlyFlagged} flagged`);
    } catch {
      setUploadNotice(`Could not parse ${file.name} as JSONL/JSON`);
    }
  };

  const handleCopyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1600);
    } catch {}
  };

  const stopStreaming = () => {
    abortControllerRef.current?.abort();
    setIsStreaming(false);
  };

  const runCopilotQuery = async (question: string, overrideMode?: CopilotMode) => {
    const trimmed = question.trim();
    if (!trimmed || isStreaming) return;

    const activeMode = overrideMode || copilotMode;
    const userMsgId = `u_${Date.now()}`;
    const assistantMsgId = `a_${Date.now() + 1}`;

    const historyPayload = messages
      .filter((m) => m.id !== 'welcome' && !m.isError && m.content.trim().length > 0)
      .slice(-8)
      .map((m) => ({ role: m.role, content: m.content }));

    const userMsg: CopilotMessage = {
      id: userMsgId,
      role: 'user',
      content: trimmed,
      mode: activeMode,
    };

    const initialAssistantMsg: CopilotMessage = {
      id: assistantMsgId,
      role: 'assistant',
      content: '',
      mode: activeMode,
    };

    setMessages((prev) => [...prev, userMsg, initialAssistantMsg]);
    setChatInput('');
    setIsStreaming(true);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const response = await fetch('/api/copilot/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: trimmed,
          mode: activeMode,
          events,
          history: historyPayload,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        let errorMsg = `HTTP ${response.status}`;
        try {
          const errJson = (await response.json()) as { error?: string };
          if (errJson.error) errorMsg = errJson.error;
        } catch {}
        throw new Error(errorMsg);
      }

      if (!response.body) {
        throw new Error('Streaming response body is unavailable.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      const processSseBlock = (block: string) => {
        const lines = block.split('\n');
        let eventName = 'message';
        const dataLines: string[] = [];
        for (const line of lines) {
          if (line.startsWith('event:')) eventName = line.slice(6).trim();
          else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
        }
        if (!dataLines.length) return;
        const payload = JSON.parse(dataLines.join('\n')) as Record<string, unknown>;

        if (eventName === 'meta') {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId
                ? {
                    ...m,
                    citations: (payload.citations as ForensicEvent[]) || [],
                    dslQuery: (payload.dslQuery as Record<string, unknown>) || undefined,
                    mitreTechniques: (payload.mitreTechniques as string[]) || [],
                  }
                : m,
            ),
          );
        } else if (eventName === 'delta') {
          const textDelta = String(payload.text || '');
          setMessages((prev) =>
            prev.map((m) => (m.id === assistantMsgId ? { ...m, content: m.content + textDelta } : m)),
          );
        } else if (eventName === 'done') {
          const followUps = Array.isArray(payload.followUps) ? (payload.followUps as string[]) : [];
          setMessages((prev) =>
            prev.map((m) => (m.id === assistantMsgId ? { ...m, followUps } : m)),
          );
        } else if (eventName === 'error') {
          const errText = String(payload.error || 'Copilot streaming failed.');
          setMessages((prev) =>
            prev.map((m) =>
              m.id === assistantMsgId ? { ...m, content: errText, isError: true } : m,
            ),
          );
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const blocks = buffer.split('\n\n');
        buffer = blocks.pop() || '';
        for (const block of blocks) {
          if (block.trim()) processSseBlock(block);
        }
      }
      if (buffer.trim()) processSseBlock(buffer);
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId && !m.content
              ? { ...m, content: 'Generation stopped by investigator.' }
              : m,
          ),
        );
      } else {
        const msg = err instanceof Error ? err.message : 'Unable to reach Copilot server.';
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId ? { ...m, content: msg, isError: true } : m,
          ),
        );
      }
    } finally {
      setIsStreaming(false);
      abortControllerRef.current = null;
    }
  };

  const renderInlineTokens = (line: string, keyPrefix: string) => {
    const tokens = line.split(/(\[DOC:[A-Za-z0-9_-]+\]|\*\*[^*]+\*\*|`[^`]+`)/g);
    return tokens.map((tok, idx) => {
      const docMatch = tok.match(/^\[DOC:([A-Za-z0-9_-]+)\]$/);
      if (docMatch) {
        const docId = docMatch[1];
        return (
          <button
            key={`${keyPrefix}_${idx}`}
            type="button"
            onClick={() => setSelectedDocId(docId)}
            className="inline-flex items-center px-1.5 py-0.5 mx-0.5 rounded bg-sky-50 border border-sky-300 text-sky-800 hover:bg-sky-100 font-mono text-[11px] font-semibold transition-colors"
          >
            DOC:{docId.slice(0, 8)}
          </button>
        );
      }
      if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4) {
        return (
          <strong key={`${keyPrefix}_${idx}`} className="font-semibold text-slate-900">
            {tok.slice(2, -2)}
          </strong>
        );
      }
      if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2) {
        return (
          <code
            key={`${keyPrefix}_${idx}`}
            className="px-1.5 py-0.5 mx-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] text-indigo-700"
          >
            {tok.slice(1, -1)}
          </code>
        );
      }
      return <React.Fragment key={`${keyPrefix}_${idx}`}>{tok}</React.Fragment>;
    });
  };

  const renderRichMessage = (text: string, msgId: string) => {
    const segments = text.split(/(```[\s\S]*?```)/g);
    return (
      <div className="space-y-2 leading-relaxed">
        {segments.map((seg, sIdx) => {
          if (seg.startsWith('```') && seg.endsWith('```')) {
            const inner = seg.slice(3, -3);
            const firstNewline = inner.indexOf('\n');
            const lang = firstNewline !== -1 ? inner.slice(0, firstNewline).trim() : '';
            const code = firstNewline !== -1 ? inner.slice(firstNewline + 1).trimEnd() : inner.trim();
            const blockKey = `${msgId}_code_${sIdx}`;
            return (
              <div key={blockKey} className="rounded-lg border border-slate-700/70 bg-slate-900 overflow-hidden my-1.5">
                <div className="px-3 py-1.5 bg-slate-800 border-b border-slate-700 flex items-center justify-between text-[10px] font-mono text-slate-300">
                  <span>{lang || 'code'}</span>
                  <button
                    type="button"
                    onClick={() => handleCopyText(blockKey, code)}
                    className="inline-flex items-center gap-1 text-sky-300 hover:text-white"
                  >
                    {copiedId === blockKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedId === blockKey ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="p-3 text-[11px] font-mono text-sky-50 overflow-x-auto whitespace-pre">{code}</pre>
              </div>
            );
          }

          return seg.split('\n').map((line, lIdx) => {
            const trimmed = line.trim();
            if (!trimmed) return <div key={`${msgId}_${sIdx}_${lIdx}`} className="h-1" />;
            if (trimmed.startsWith('### ') || trimmed.startsWith('## ')) {
              return (
                <div key={`${msgId}_${sIdx}_${lIdx}`} className="text-xs font-bold text-indigo-800 pt-1 font-display">
                  {renderInlineTokens(trimmed.replace(/^#{2,3}\s+/, ''), `${msgId}_${sIdx}_${lIdx}`)}
                </div>
              );
            }
            if (/^[-*•]\s+/.test(trimmed)) {
              return (
                <div key={`${msgId}_${sIdx}_${lIdx}`} className="flex items-start gap-2 pl-1">
                  <span className="text-sky-600 mt-0.5">•</span>
                  <div className="flex-1 min-w-0">
                    {renderInlineTokens(trimmed.replace(/^[-*•]\s+/, ''), `${msgId}_${sIdx}_${lIdx}`)}
                  </div>
                </div>
              );
            }
            return (
              <p key={`${msgId}_${sIdx}_${lIdx}`}>
                {renderInlineTokens(line, `${msgId}_${sIdx}_${lIdx}`)}
              </p>
            );
          });
        })}
      </div>
    );
  };

  const navItems = [
    { key: 'triage', label: 'Alerts', icon: Activity },
    { key: 'all', label: 'All Events', icon: ListFilter },
    { key: 'graph', label: 'Attack Graph', icon: Network },
    { key: 'rules', label: 'Sigma Rules', icon: ShieldCheck },
    { key: 'history', label: `History (${history.length})`, icon: History },
  ] as const;

  return (
    <div className="min-h-screen flex flex-col lg:flex-row lab-grid-bg text-slate-900">
      {/* Left Vertical Command Rail (Top bar on <lg, Sidebar on lg+) */}
      <aside className="lg:w-60 shrink-0 bg-white/92 backdrop-blur-md border-b lg:border-b-0 lg:border-r border-slate-200 flex flex-col justify-between lg:sticky lg:top-0 lg:h-screen z-20">
        <div className="p-4 lg:p-5 space-y-5">
          {/* Brand Header */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="10.5" cy="10.5" r="7" fill="rgba(2,132,199,0.10)" stroke="#0284C7" strokeWidth="1.9" />
                <circle cx="10.5" cy="10.5" r="3" stroke="#4F46E5" strokeWidth="1.2" strokeOpacity="0.85" />
                <path d="M15.8 15.8L20.5 20.5" stroke="#0284C7" strokeWidth="2.2" strokeLinecap="round" />
              </svg>
              <span className="text-base font-bold tracking-tight text-slate-900 font-display">
                ForensicLens
              </span>
            </div>

            <button
              type="button"
              onClick={() => {
                setEvents((prev) => prev.map((e) => evaluateSigmaRules(e)));
                setUploadNotice(`Scanned ${events.length} events`);
              }}
              className="lg:hidden px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg whitespace-nowrap shrink-0 transition-colors"
            >
              Scan Logs
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible pb-1 lg:pb-0">
            {navItems.map(({ key, label, icon: Icon }) => {
              const isActive = view === key;
              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => setView(key)}
                  className={`flex items-center gap-2.5 px-3 py-2 text-xs rounded-lg whitespace-nowrap shrink-0 transition-colors ${
                    isActive
                      ? 'bg-sky-50 text-sky-800 border border-sky-200 font-semibold shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/80 border border-transparent font-medium'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-600' : 'text-slate-400'}`} />
                  <span>{label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Bottom Case Actions */}
        <div className="hidden lg:flex flex-col gap-2 p-5 border-t border-slate-200 bg-slate-50/70">
          <button
            type="button"
            onClick={() => {
              setEvents((prev) => prev.map((e) => evaluateSigmaRules(e)));
              setUploadNotice(`Scanned ${events.length} events`);
            }}
            className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg whitespace-nowrap transition-colors shadow-xs"
          >
            <ScanLine className="w-3.5 h-3.5" />
            Scan Logs
          </button>
          <button
            type="button"
            onClick={handleExportReport}
            disabled={events.length === 0}
            className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg whitespace-nowrap transition-colors disabled:opacity-45"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
          <button
            type="button"
            onClick={handleClearHistory}
            className="w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 text-xs font-medium text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 rounded-lg whitespace-nowrap transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear History
          </button>
        </div>
      </aside>

      {/* Main Content Area: Top Telemetry Deck + Bottom Split Investigation Canvas */}
      <div className="flex-1 min-w-0 p-5 lg:p-6 space-y-5">
        {/* Top Artifact Ingestion Strip */}
        <section className="space-y-2.5">
          <div
            role="button"
            tabIndex={0}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
            }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              handleFileImport(e.dataTransfer.files[0]);
            }}
            className="lab-panel border-dashed border-sky-400/60 hover:border-sky-500 hover:bg-sky-50/40 rounded-xl px-5 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 cursor-pointer transition-colors shadow-xs"
          >
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="text-sm font-semibold text-slate-900 font-display">
                  Upload Windows Log Artifact
                </h1>
                <span className="text-xs font-mono text-slate-500">
                  {activeFileName ? `· Active: ${activeFileName}` : '· No active artifact'}
                </span>
                {tacticFilter && (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setTacticFilter('');
                    }}
                    className="px-2 py-0.5 rounded bg-sky-100 border border-sky-300 text-sky-800 font-mono text-[11px] hover:bg-sky-200"
                  >
                    Tactic: {tacticFilter} ×
                  </button>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Drag and drop <span className="font-mono text-sky-700 font-medium">.jsonl</span> or{' '}
                <span className="font-mono text-sky-700 font-medium">.evtx</span> logs to populate the Threat Radar and Attack Graph.
              </p>
              {uploadNotice && (
                <p className="text-xs font-medium text-indigo-700 mt-1 font-mono">{uploadNotice}</p>
              )}
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-sky-800 bg-sky-50 border border-sky-200 rounded-lg whitespace-nowrap">
                <FileUp className="w-3.5 h-3.5" />
                Choose File
              </span>
              <input
                ref={fileInputRef}
                type="file"
                accept=".jsonl,.json,.evtx"
                className="hidden"
                onChange={(e) => handleFileImport(e.target.files?.[0])}
              />
            </div>
          </div>

          {/* Mobile Quick Case Actions */}
          <div className="flex lg:hidden items-center justify-end gap-2">
            <button
              type="button"
              onClick={handleExportReport}
              disabled={events.length === 0}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg disabled:opacity-45"
            >
              <Download className="w-3.5 h-3.5" />
              Export Report
            </button>
            <button
              type="button"
              onClick={handleClearHistory}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-rose-700 bg-rose-50 border border-rose-200 rounded-lg"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear History
            </button>
          </div>
        </section>

        {/* Full-Width Telemetry Deck: Threat Radar + 4 Radial Severity Gauges */}
        <ThreatTelemetryHud
          events={events}
          severityFilter={severityFilter}
          tacticFilter={tacticFilter}
          onSelectSeverity={setSeverityFilter}
          onSelectTactic={(tactic) => {
            setTacticFilter(tactic);
            if (view !== 'triage' && view !== 'all') setView('triage');
          }}
        />

        {/* Bottom 12-Col Split Investigation Canvas */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* Left 7 Cols: Active Workspace View */}
          <section className="xl:col-span-7 flex flex-col gap-4 min-w-0">
            {view === 'triage' || view === 'all' ? (
              <>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-1 p-1 bg-white border border-slate-200 rounded-lg shadow-2xs">
                    {[
                      { key: '', label: 'All' },
                      { key: 'critical', label: 'Critical' },
                      { key: 'high', label: 'High' },
                      { key: 'medium', label: 'Medium' },
                    ].map((tab) => (
                      <button
                        key={tab.label}
                        type="button"
                        onClick={() => setSeverityFilter(tab.key)}
                        className={`px-3 py-1.5 text-xs rounded-md whitespace-nowrap transition-colors ${
                          severityFilter === tab.key
                            ? 'bg-indigo-600 text-white font-semibold'
                            : 'text-slate-600 font-medium hover:text-slate-900'
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  <div className="relative flex-1 max-w-md">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="search"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Filter by host, user, EventID, or command..."
                      className="w-full pl-9 pr-3.5 py-2 text-xs bg-white border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-sky-500 shadow-2xs"
                    />
                  </div>
                </div>

                <div className="lab-panel rounded-xl overflow-hidden flex-1 flex flex-col shadow-xs">
                  <div className="divide-y divide-slate-200/80 overflow-y-auto max-h-[540px]">
                    {filteredEvents.map((evt) => {
                      const style = severityMeta(evt.sigma_severity);
                      return (
                        <button
                          key={evt.doc_id}
                          type="button"
                          onClick={() => setSelectedDocId(evt.doc_id)}
                          className={`w-full text-left px-4 py-3.5 hover:bg-sky-50/70 transition-colors flex flex-col gap-1.5 ${
                            selectedDocId === evt.doc_id ? 'bg-sky-50' : ''
                          }`}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2.5 min-w-0">
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-semibold font-mono shrink-0 ${style.bg} ${style.border} ${style.text}`}
                              >
                                {style.label}
                              </span>
                              <span className="text-xs font-semibold text-slate-900 truncate">
                                {evt.sigma_alerts.length > 0
                                  ? evt.sigma_alerts.map((a) => a.title).join(' · ')
                                  : evt.message || `Windows Event ${evt.event_id}`}
                              </span>
                            </div>
                            <span className="text-[11px] font-mono tabular-nums text-slate-500 shrink-0">
                              {formatTs(evt.timestamp)}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {evt.host} · {evt.user} · Event {evt.event_id}
                          </div>
                          {evt.command_line && (
                            <div className="text-[11px] font-mono text-slate-800 bg-slate-100 border border-slate-200 rounded-md px-2.5 py-1 truncate">
                              {evt.command_line}
                            </div>
                          )}
                        </button>
                      );
                    })}
                  </div>

                  {filteredEvents.length === 0 && (
                    <div className="py-16 px-6 text-center space-y-1.5">
                      <p className="text-sm font-semibold text-slate-900 font-display">
                        {events.length > 0 ? 'No matching events for current filter' : 'No events in active case'}
                      </p>
                      <p className="text-xs text-slate-500">
                        {events.length > 0
                          ? 'Clear your severity, tactic, or search filter to inspect all events.'
                          : 'Upload a Windows .jsonl or .evtx artifact above to initialize Threat Radar and triage.'}
                      </p>
                    </div>
                  )}
                </div>
              </>
            ) : view === 'graph' ? (
              <AttackGraphPanel events={events} onSelectDoc={(docId) => setSelectedDocId(docId)} />
            ) : view === 'rules' ? (
              <div className="lab-panel rounded-xl p-5 space-y-3 shadow-xs">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-sky-600" />
                  <h2 className="text-sm font-semibold text-slate-900 font-display">
                    Automated Sigma Detection Rules
                  </h2>
                </div>
                <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg bg-white">
                  {SIGMA_RULES_CATALOG.map((rule) => {
                    const style = severityMeta(rule.severity);
                    return (
                      <div key={rule.rule_id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div>
                          <div className="text-xs font-semibold text-slate-900">{rule.title}</div>
                          <div className="text-xs text-slate-500 mt-0.5 font-mono">
                            {rule.rule_id} · {rule.mitre_tactic} ({rule.mitre_technique})
                          </div>
                          <div className="text-xs text-slate-600 mt-1">{rule.description}</div>
                        </div>
                        <span
                          className={`px-2.5 py-1 rounded-md border text-[11px] font-semibold font-mono shrink-0 ${style.bg} ${style.border} ${style.text}`}
                        >
                          {style.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="lab-panel rounded-xl p-5 space-y-3 shadow-xs">
                <div>
                  <h2 className="text-sm font-semibold text-slate-900 font-display">Saved Investigation History</h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Sessions archived when you click Clear Chat. Open any past case to restore its Threat Radar, Graph, and chat.
                  </p>
                </div>
                {history.length === 0 ? (
                  <div className="py-12 text-center border border-slate-200 rounded-lg text-xs text-slate-500 bg-slate-50">
                    No saved sessions yet. Upload a log file and click Clear Chat to archive it here.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg bg-white">
                    {history.map((item) => (
                      <div key={item.id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-slate-900 truncate">{item.filename}</div>
                          <div className="text-xs text-slate-500 mt-0.5 font-mono tabular-nums">
                            {formatTs(item.savedAt)} · {item.totalEvents} events · {item.flaggedEvents} flagged
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => handleRestoreSession(item)}
                            className="px-3 py-1.5 text-xs font-semibold text-sky-800 bg-sky-50 hover:bg-sky-100 border border-sky-200 rounded-md transition-colors"
                          >
                            Open
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteHistoryItem(item.id)}
                            className="px-3 py-1.5 text-xs font-medium text-slate-600 hover:text-rose-700 bg-white hover:bg-rose-50 border border-slate-200 rounded-md transition-colors"
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Right 5 Cols: ForensicLens AI Copilot Terminal */}
          <aside className="xl:col-span-5 lab-panel rounded-xl flex flex-col overflow-hidden min-h-[580px] xl:h-[640px] shadow-xs">
            <div className="px-5 py-3.5 border-b border-slate-200 bg-white flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white flex items-center justify-center shrink-0">
                  <Sparkles className="w-3.5 h-3.5" />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-slate-900 truncate font-display">
                    ForensicLens AI Copilot
                  </h2>
                  <p className="text-[11px] text-slate-500 truncate font-mono">
                    Multi-Turn DFIR Agent · {events.length} indexed
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleClearChatAndResetPage}
                className="px-3 py-1 text-xs font-medium text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-md whitespace-nowrap"
              >
                Clear Chat
              </button>
            </div>

            {/* Mode Selector */}
            <div className="px-4 py-2.5 border-b border-slate-200 bg-slate-50/80 flex items-center gap-1.5 overflow-x-auto">
              {COPILOT_MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setCopilotMode(m.id)}
                  className={`px-2.5 py-1 text-xs rounded-md whitespace-nowrap transition-colors ${
                    copilotMode === m.id
                      ? 'bg-indigo-600 text-white font-semibold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/70 font-medium'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {/* Streaming Chat Feed */}
            <div ref={chatScrollRef} className="flex-1 overflow-y-auto p-4 space-y-3.5 bg-slate-50/60">
              {messages.map((msg, msgIndex) => {
                const isLatestAssistant =
                  msg.role === 'assistant' && msgIndex === messages.length - 1;
                return (
                  <div
                    key={msg.id}
                    className={
                      msg.role === 'user'
                        ? 'ml-8 border border-indigo-200 bg-indigo-50/90 rounded-xl p-3.5 text-xs text-slate-900'
                        : msg.isError
                          ? 'border border-rose-200 bg-rose-50 rounded-xl p-3.5 text-xs text-rose-800 space-y-2'
                          : 'border border-slate-200 bg-white rounded-xl p-3.5 text-xs text-slate-700 space-y-2.5 shadow-2xs'
                    }
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-500">
                        {msg.isError && <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />}
                        <span>
                          {msg.role === 'user' ? 'Investigator' : 'ForensicLens AI Copilot'}
                        </span>
                        {msg.mode && (
                          <span className="font-mono text-[10px] text-sky-700 uppercase">
                            · {msg.mode.replace('_', ' ')}
                          </span>
                        )}
                      </div>
                      {msg.role === 'assistant' && msg.content && !msg.isError && (
                        <button
                          type="button"
                          onClick={() => handleCopyText(msg.id, msg.content)}
                          className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-sky-700"
                        >
                          {copiedId === msg.id ? (
                            <Check className="w-3 h-3 text-emerald-600" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          {copiedId === msg.id ? 'Copied' : 'Copy'}
                        </button>
                      )}
                    </div>

                    {msg.role === 'assistant' ? (
                      msg.content ? (
                        <>
                          {renderRichMessage(msg.content, msg.id)}
                          {msg.isError && msgIndex > 0 && messages[msgIndex - 1]?.role === 'user' && (
                            <button
                              type="button"
                              disabled={isStreaming}
                              onClick={() => runCopilotQuery(messages[msgIndex - 1].content, msg.mode)}
                              className="mt-2 px-3 py-1 text-[11px] font-semibold text-white bg-rose-600 hover:bg-rose-700 rounded-md"
                            >
                              Retry Query
                            </button>
                          )}
                        </>
                      ) : (
                        <div className="text-sky-700 italic font-mono">Correlating log telemetry...</div>
                      )
                    ) : (
                      <div className="whitespace-pre-wrap leading-relaxed">{msg.content}</div>
                    )}

                    {msg.mitreTechniques && msg.mitreTechniques.length > 0 && (
                      <div className="text-[11px] font-mono text-amber-700 font-medium pt-1">
                        MITRE ATT&amp;CK: {msg.mitreTechniques.join(' · ')}
                      </div>
                    )}

                    {msg.citations && msg.citations.length > 0 && (
                      <div className="pt-2 border-t border-slate-200 space-y-1.5">
                        <div className="text-[11px] font-medium text-slate-500">Cited Log Events</div>
                        {msg.citations.slice(0, 4).map((c) => {
                          const style = severityMeta(c.sigma_severity);
                          return (
                            <button
                              key={c.doc_id}
                              type="button"
                              onClick={() => setSelectedDocId(c.doc_id)}
                              className="w-full text-left px-2.5 py-1.5 rounded-lg bg-slate-50 hover:bg-sky-50 border border-slate-200 hover:border-sky-300 flex items-center justify-between gap-2 transition-colors"
                            >
                              <span className="font-mono text-[11px] text-slate-800 truncate">
                                {c.host} · Event {c.event_id} · {c.command_line || c.message}
                              </span>
                              <span
                                className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold font-mono shrink-0 ${style.bg} ${style.border} ${style.text}`}
                              >
                                {style.label}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    )}

                    {msg.dslQuery && (
                      <details className="pt-1 text-[11px] text-slate-500">
                        <summary className="cursor-pointer hover:text-sky-700">Inspect OpenSearch DSL</summary>
                        <pre className="mt-2 p-2.5 rounded-lg bg-slate-900 border border-slate-700 font-mono text-[11px] text-sky-100 overflow-x-auto">
                          {JSON.stringify(msg.dslQuery, null, 2)}
                        </pre>
                      </details>
                    )}

                    {isLatestAssistant && msg.followUps && msg.followUps.length > 0 && !isStreaming && (
                      <div className="pt-2 border-t border-slate-200 space-y-1.5">
                        <div className="text-[11px] font-medium text-slate-500">Suggested Follow-Ups</div>
                        <div className="flex flex-wrap gap-1.5">
                          {msg.followUps.map((q) => (
                            <button
                              key={q}
                              type="button"
                              onClick={() => runCopilotQuery(q)}
                              className="px-2.5 py-1 text-[11px] font-medium text-sky-800 bg-sky-50 hover:bg-sky-100 border border-sky-200 rounded-md transition-colors text-left"
                            >
                              {q}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                runCopilotQuery(chatInput);
              }}
              className="p-3.5 border-t border-slate-200 bg-white"
            >
              <div className="flex items-end gap-2">
                <textarea
                  rows={2}
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      runCopilotQuery(chatInput);
                    }
                  }}
                  placeholder={
                    COPILOT_MODES.find((m) => m.id === copilotMode)?.placeholder ||
                    'Ask ForensicLens Copilot...'
                  }
                  className="flex-1 px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 resize-none focus:outline-none focus:border-sky-500"
                />
                {isStreaming ? (
                  <button
                    type="button"
                    onClick={stopStreaming}
                    className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-700 rounded-lg whitespace-nowrap shrink-0"
                  >
                    <Square className="w-3 h-3 fill-current" />
                    Stop
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={!chatInput.trim()}
                    className="px-4 py-2.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-45 rounded-lg whitespace-nowrap shrink-0"
                  >
                    Investigate
                  </button>
                )}
              </div>
            </form>
          </aside>
        </div>
      </div>

      {/* Evidence Inspector Slide-Over Drawer */}
      {selectedEvent && (
        <>
          <div onClick={() => setSelectedDocId(null)} className="fixed inset-0 bg-slate-900/35 backdrop-blur-xs z-40" />
          <aside className="fixed top-0 right-0 h-full w-full max-w-xl bg-white border-l border-slate-200 z-50 flex flex-col shadow-2xl">
            <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="text-xs font-mono text-sky-700 font-semibold truncate">
                  DOC:{selectedEvent.doc_id}
                </div>
                <h3 className="text-sm font-semibold text-slate-900 mt-0.5 font-display">
                  Event Evidence Inspector
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedDocId(null)}
                className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
              {selectedEvent.sigma_alerts.length > 0 && (
                <div className="border border-rose-200 bg-rose-50 rounded-xl p-4 space-y-2">
                  <div className="text-xs font-semibold text-rose-800 font-display">
                    Matched Sigma Detections
                  </div>
                  {selectedEvent.sigma_alerts.map((a) => (
                    <div key={a.rule_id} className="pt-2 border-t border-rose-200 first:border-t-0 first:pt-0">
                      <div className="font-semibold text-slate-900">
                        {a.title} ({a.severity.toUpperCase()})
                      </div>
                      <div className="font-mono text-rose-700 mt-0.5">
                        {a.rule_id} · {a.mitre_tactic} · {a.mitre_technique}
                      </div>
                      <div className="text-slate-700 mt-1">{a.description}</div>
                    </div>
                  ))}
                </div>
              )}

              {decodedPowerShell && (
                <div className="border border-sky-200 bg-sky-50 rounded-xl p-4 space-y-1.5">
                  <div className="text-xs font-semibold text-sky-900 font-display">
                    Decoded Base64 PowerShell Payload
                  </div>
                  <pre className="font-mono text-[11px] text-sky-50 bg-slate-900 border border-slate-700 rounded-lg p-2.5 whitespace-pre-wrap break-all">
                    {decodedPowerShell}
                  </pre>
                </div>
              )}

              <div className="border border-slate-200 rounded-xl divide-y divide-slate-200 bg-white overflow-hidden">
                {(
                  [
                    ['Timestamp', selectedEvent.timestamp],
                    ['Channel', selectedEvent.channel],
                    ['Event ID', selectedEvent.event_id],
                    ['Host', selectedEvent.host],
                    ['User', selectedEvent.user],
                    ['Process', selectedEvent.process_name],
                    ['Parent Process', selectedEvent.parent_process],
                    ['Command Line', selectedEvent.command_line],
                    ['Target Image', selectedEvent.target_image],
                    ['Granted Access', selectedEvent.granted_access],
                    ['Logon Type', selectedEvent.logon_type],
                    ['Source IP', selectedEvent.source_ip],
                  ] as const
                )
                  .filter(([, val]) => Boolean(val))
                  .map(([label, val]) => (
                    <div key={label} className="px-4 py-2.5 grid grid-cols-3 gap-3">
                      <div className="font-medium text-slate-500">{label}</div>
                      <div className="col-span-2 font-mono text-slate-900 break-all">{val}</div>
                    </div>
                  ))}
              </div>

              <details className="bg-slate-50 border border-slate-200 rounded-xl p-3.5">
                <summary className="cursor-pointer font-semibold text-slate-800">Inspect Raw Event JSON</summary>
                <pre className="mt-3 p-3 rounded-lg bg-slate-900 border border-slate-700 font-mono text-[11px] text-sky-100 overflow-x-auto">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </details>
            </div>
          </aside>
        </>
      )}
    </div>
  );
}
