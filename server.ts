import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, ThinkingLevel } from '@google/genai';
import { createServer as createViteServer } from 'vite';

interface SigmaAlertInput {
  rule_id: string;
  title: string;
  severity: string;
  mitre_tactic: string;
  mitre_technique: string;
  description?: string;
}

interface ForensicEventInput {
  doc_id: string;
  timestamp: string;
  channel?: string;
  event_id: string;
  host: string;
  user: string;
  process_name?: string;
  parent_process?: string;
  command_line?: string;
  target_image?: string;
  granted_access?: string;
  logon_type?: string;
  source_ip?: string;
  message?: string;
  sigma_flagged?: boolean;
  sigma_severity?: string;
  sigma_alerts?: SigmaAlertInput[];
}

interface HistoryTurn {
  role: 'user' | 'assistant';
  content: string;
}

type CopilotMode = 'investigate' | 'hunt' | 'remediate' | 'sigma_rule';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error(
      'GEMINI_API_KEY is not configured. Set your Gemini API key in Settings > Secrets to use ForensicLens AI Copilot.',
    );
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function decodePowerShellBase64(commandLine: string | undefined): string | null {
  if (!commandLine) return null;
  const match = commandLine.match(/(?:-EncodedCommand|-enc|-ec|-e)\s+([A-Za-z0-9+/=]{16,})/i);
  if (!match) return null;
  try {
    const buf = Buffer.from(match[1], 'base64');
    const decoded = buf.toString('utf16le').replace(/\0/g, '').trim();
    return decoded || null;
  } catch {
    return null;
  }
}

function rankRelevantEvents(
  question: string,
  events: ForensicEventInput[],
  limit = 16,
): ForensicEventInput[] {
  const tokens = question
    .toLowerCase()
    .split(/[^a-z0-9._\\:-]+/)
    .filter((t) => t.length >= 2);

  const scored = events.map((evt) => {
    let score = 0;
    if (evt.sigma_flagged) score += 4;
    if (evt.sigma_severity === 'critical') score += 5;
    else if (evt.sigma_severity === 'high') score += 3;
    else if (evt.sigma_severity === 'medium') score += 2;

    const hay = [
      evt.host,
      evt.user,
      evt.event_id,
      evt.process_name,
      evt.command_line,
      evt.target_image,
      evt.source_ip,
      evt.message,
      ...(evt.sigma_alerts || []).map((a) => `${a.title} ${a.mitre_technique} ${a.mitre_tactic}`),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    for (const tok of tokens) {
      if (hay.includes(tok)) score += 4;
    }
    return { evt, score };
  });

  return scored
    .sort((a, b) => b.score - a.score || a.evt.timestamp.localeCompare(b.evt.timestamp))
    .slice(0, limit)
    .map((s) => s.evt)
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

function buildDslPreview(question: string, mode: CopilotMode): Record<string, unknown> {
  const mustOrFilter: Record<string, unknown>[] = [];
  if (mode === 'hunt' || mode === 'investigate') {
    mustOrFilter.push({ term: { sigma_flagged: { value: true, boost: 1.5 } } });
  }
  return {
    bool: {
      should: [
        {
          multi_match: {
            query: question,
            fields: ['command_line^3', 'process_name^2', 'message^2', 'target_image', 'user', 'host', 'source_ip'],
            fuzziness: 'AUTO',
          },
        },
        {
          knn: {
            command_embedding: {
              vector: '<384-dim all-MiniLM-L6-v2>',
              k: 8,
            },
          },
        },
        ...mustOrFilter,
      ],
      minimum_should_match: 1,
    },
  };
}

function buildModeSystemInstruction(mode: CopilotMode): string {
  const baseRules = `You are ForensicLens AI Copilot, a principal Digital Forensics & Incident Response (DFIR) analyst and threat hunter.
Strictly ground every factual claim in the provided Windows log evidence.

Formatting & Citation Rules:
1. Cite every factual claim inline using exact tokens like [DOC:<doc_id>] (never alter the doc_id).
2. Never fabricate hosts, usernames, IPs, PIDs, hashes, or timestamps not present in the evidence.
3. If an event has a decoded Base64 PowerShell payload provided in the evidence, analyze the decoded script directly.
4. Use crisp markdown sections (**bold** headers, bullet points, inline \`code\`, and fenced code blocks where appropriate).
5. At the very end of your response, include a single line starting with FOLLOWUPS_JSON: followed by a valid JSON array of 3 concise follow-up questions the investigator should ask next (under 9 words each).`;

  if (mode === 'hunt') {
    return `${baseRules}

Active Mode: THREAT HUNT
- Correlate pivot points across hosts, users, parent/child processes, logon types, and external IPs.
- Identify lateral movement paths, persistence gaps, and additional artifacts to inspect (e.g., Sysmon EID 1/3/10/11, Security 4624/4625/4688, PowerShell 4104).`;
  }
  if (mode === 'remediate') {
    return `${baseRules}

Active Mode: CONTAIN & REMEDIATE
- Provide prioritized incident response steps split into: (1) Immediate Containment, (2) Credential & Access Eradication, (3) Evidence Preservation & Recovery.
- Include exact, copy-ready Windows PowerShell / netsh / defender commands tailored to the cited host, user, and malicious processes.`;
  }
  if (mode === 'sigma_rule') {
    return `${baseRules}

Active Mode: SIGMA & OPENSEARCH RULE BUILDER
- Based on the observed adversary behavior in the cited events, write:
  1. A production-ready Sigma YAML detection rule (with \`title\`, \`status\`, \`logsource\`, \`detection\`, \`falsepositives\`, \`level\`, and MITRE \`tags\`).
  2. A corresponding OpenSearch Query DSL JSON snippet to hunt this pattern across historical logs.`;
  }
  return `${baseRules}

Active Mode: FORENSIC TIMELINE & ROOT CAUSE INVESTIGATION
- Reconstruct the chronological attack chain from initial access through impact.
- Highlight MITRE ATT&CK tactics/techniques, compromised accounts, suspicious commands, and key IOCs.`;
}

function buildFollowUpFallback(mode: CopilotMode, events: ForensicEventInput[]): string[] {
  const hasPs = events.some((e) => (e.command_line || '').toLowerCase().includes('-enc'));
  const hasLsass = events.some((e) => (e.target_image || '').toLowerCase().includes('lsass'));
  if (mode === 'investigate') {
    return [
      hasLsass ? 'Which account accessed LSASS memory?' : 'Check for credential dumping indicators',
      hasPs ? 'What does the decoded PowerShell script do?' : 'Hunt for lateral movement across hosts',
      'Give me immediate containment commands',
    ];
  }
  if (mode === 'hunt') {
    return [
      'Generate a Sigma rule for this behavior',
      'List all unique external IPs and users',
      'Draft an incident containment playbook',
    ];
  }
  if (mode === 'remediate') {
    return [
      'Write a Sigma YAML rule to block recurrence',
      'Which forensic artifacts should we preserve first?',
      'Summarize executive incident timeline',
    ];
  }
  return [
    'Explain how to tune false positives for this rule',
    'Give me containment steps for the affected host',
    'Summarize the full attack timeline',
  ];
}

async function startServer(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: '4mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      copilotModel: 'gemini-4-hydrogen',
      geminiConfigured: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'),
    });
  });

  app.post('/api/copilot/stream', async (req, res) => {
    const body = req.body as {
      question?: string;
      mode?: CopilotMode;
      events?: ForensicEventInput[];
      history?: HistoryTurn[];
    };

    const question = (body.question || '').trim();
    const mode: CopilotMode =
      body.mode && ['investigate', 'hunt', 'remediate', 'sigma_rule'].includes(body.mode)
        ? body.mode
        : 'investigate';
    const events = Array.isArray(body.events) ? body.events : [];
    const history = Array.isArray(body.history) ? body.history.slice(-10) : [];

    if (!question) {
      res.status(400).json({ error: 'Question cannot be empty.' });
      return;
    }

    let ai: GoogleGenAI;
    try {
      ai = getGeminiClient();
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Gemini initialization failed.' });
      return;
    }

    const relevantEvents = rankRelevantEvents(question, events, 16);
    const dslQuery = buildDslPreview(question, mode);
    const mitreTechniques = Array.from(
      new Set(
        relevantEvents.flatMap((e) =>
          (e.sigma_alerts || []).map((a) => `${a.mitre_technique} (${a.mitre_tactic})`),
        ),
      ),
    );

    const evidenceBlock =
      relevantEvents.length > 0
        ? relevantEvents
            .map((e) => {
              const decoded = decodePowerShellBase64(e.command_line);
              const alerts = (e.sigma_alerts || [])
                .map((a) => `${a.rule_id}: ${a.title} [${a.severity.toUpperCase()} | ${a.mitre_technique}]`)
                .join('; ');
              return [
                `[DOC:${e.doc_id}]`,
                `Time=${e.timestamp}`,
                `Channel=${e.channel || 'Security'}`,
                `EventID=${e.event_id}`,
                `Host=${e.host}`,
                `User=${e.user}`,
                `Process=${e.process_name || '-'}`,
                e.parent_process ? `ParentProcess=${e.parent_process}` : null,
                e.command_line ? `CommandLine=${e.command_line}` : null,
                decoded ? `DecodedPowerShell=${decoded}` : null,
                e.target_image ? `TargetImage=${e.target_image}` : null,
                e.granted_access ? `GrantedAccess=${e.granted_access}` : null,
                e.logon_type ? `LogonType=${e.logon_type}` : null,
                e.source_ip ? `SourceIP=${e.source_ip}` : null,
                `Message=${e.message || '-'}`,
                `SigmaAlerts=${alerts || 'None'}`,
              ]
                .filter(Boolean)
                .join(' | ');
            })
            .join('\n')
        : 'NO_LOG_EVENTS_UPLOADED_YET';

    const conversationSummary =
      history.length > 0
        ? history
            .map((turn) => `${turn.role === 'user' ? 'Investigator' : 'ForensicLens Copilot'}: ${turn.content}`)
            .join('\n\n')
        : 'None (initial question in session).';

    const userPrompt = [
      `Total Indexed Events in Active Case: ${events.length}`,
      `Sigma Flagged Events: ${events.filter((e) => e.sigma_flagged).length}`,
      '',
      'Previous Conversation Context:',
      conversationSummary,
      '',
      `Ranked Log Evidence (${relevantEvents.length} events):`,
      evidenceBlock,
      '',
      `Current Investigator Request (${mode.toUpperCase()} mode):`,
      question,
    ].join('\n');

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const sendSse = (eventName: string, payload: unknown) => {
      res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`);
    };

    sendSse('meta', {
      citations: relevantEvents.slice(0, 6),
      dslQuery,
      mitreTechniques,
      mode,
    });

    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

    const isTransientError = (err: unknown): boolean => {
      const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
      return (
        msg.includes('503') ||
        msg.includes('unavailable') ||
        msg.includes('high demand') ||
        msg.includes('overloaded') ||
        msg.includes('econnreset') ||
        msg.includes('etimedout')
      );
    };

    const formatGeminiError = (err: unknown): string => {
      const raw = err instanceof Error ? err.message : String(err);
      const nestedMatch = raw.match(/"message"\s*:\s*"([^"]+)"/);
      if (nestedMatch) {
        return nestedMatch[1].replace(/\\n/g, ' ').trim();
      }
      return raw;
    };

    const attempts: { model: string; thinkingLevel: ThinkingLevel; delayMs: number }[] = [
      {
        model: 'gemini-4-hydrogen',
        thinkingLevel: mode === 'investigate' ? ThinkingLevel.LOW : ThinkingLevel.MEDIUM,
        delayMs: 0,
      },
      {
        model: 'gemini-4-hydrogen',
        thinkingLevel: mode === 'investigate' ? ThinkingLevel.LOW : ThinkingLevel.MEDIUM,
        delayMs: 650,
      },
      {
        model: 'gemini-3.1-flash-lite',
        thinkingLevel: ThinkingLevel.MINIMAL,
        delayMs: 900,
      },
    ];

    let fullText = '';
    let sentCleanLength = 0;
    let lastError: unknown = null;
    let succeeded = false;

    for (let i = 0; i < attempts.length; i++) {
      const attempt = attempts[i];
      if (attempt.delayMs > 0) {
        await sleep(attempt.delayMs);
      }

      try {
        const stream = await ai.models.generateContentStream({
          model: attempt.model,
          contents: userPrompt,
          config: {
            systemInstruction: buildModeSystemInstruction(mode),
            thinkingConfig: { thinkingLevel: attempt.thinkingLevel },
          },
        });

        for await (const chunk of stream) {
          const piece = chunk.text || '';
          if (!piece) continue;
          fullText += piece;

          const markerIdx = fullText.indexOf('FOLLOWUPS_JSON:');
          const cleanText = markerIdx === -1 ? fullText : fullText.slice(0, markerIdx);
          const safeLimit =
            markerIdx === -1
              ? Math.max(sentCleanLength, cleanText.length - 16)
              : cleanText.length;

          if (safeLimit > sentCleanLength) {
            sendSse('delta', { text: cleanText.slice(sentCleanLength, safeLimit) });
            sentCleanLength = safeLimit;
          }
        }

        succeeded = true;
        break;
      } catch (err) {
        lastError = err;
        // Only retry or fall back if no partial output was emitted yet and the error is transient
        if (sentCleanLength === 0 && isTransientError(err) && i < attempts.length - 1) {
          fullText = '';
          continue;
        }
        break;
      }
    }

    if (!succeeded) {
      sendSse('error', {
        error: `AI Copilot upstream error: ${formatGeminiError(lastError)}`,
      });
      res.end();
      return;
    }

    const markerIdx = fullText.indexOf('FOLLOWUPS_JSON:');
    const finalCleanText = (markerIdx === -1 ? fullText : fullText.slice(0, markerIdx)).trimEnd();
    if (finalCleanText.length > sentCleanLength) {
      sendSse('delta', { text: finalCleanText.slice(sentCleanLength) });
    }

    let followUps = buildFollowUpFallback(mode, relevantEvents);
    if (markerIdx !== -1) {
      const rawJson = fullText.slice(markerIdx + 'FOLLOWUPS_JSON:'.length).trim();
      const arrayMatch = rawJson.match(/\[[\s\S]*\]/);
      if (arrayMatch) {
        try {
          const parsed = JSON.parse(arrayMatch[0]) as unknown;
          if (Array.isArray(parsed)) {
            const cleaned = parsed
              .filter((x): x is string => typeof x === 'string' && x.trim().length > 0)
              .slice(0, 3);
            if (cleaned.length > 0) followUps = cleaned;
          }
        } catch {
          // Keep contextual fallback follow-ups if trailing JSON was incomplete
        }
      }
    }

    sendSse('done', { followUps });
    res.end();
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ForensicLens server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start ForensicLens server:', err);
  process.exit(1);
});
