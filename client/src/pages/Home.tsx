import { useEffect, useMemo, useRef, useState } from "react";
import { AIChatBox, type Message } from "@/components/AIChatBox";
import { MarkdownContent } from "@/components/MarkdownContent";
import { ReconGraph, type GraphEdge, type GraphNode } from "@/components/ReconGraph";
import { downloadReport, markdownReport, printableHtmlReport } from "@/lib/reportExport";
import { trpc } from "@/lib/trpc";
import { startLogin } from "@/const";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import Activity from "lucide-react/dist/esm/icons/activity";
import Bot from "lucide-react/dist/esm/icons/bot";
import Check from "lucide-react/dist/esm/icons/check";
import ChevronRight from "lucide-react/dist/esm/icons/chevron-right";
import CircleDotDashed from "lucide-react/dist/esm/icons/circle-dot-dashed";
import Command from "lucide-react/dist/esm/icons/command";
import Download from "lucide-react/dist/esm/icons/download";
import ExternalLink from "lucide-react/dist/esm/icons/external-link";
import FileCode2 from "lucide-react/dist/esm/icons/file-code-2";
import FileText from "lucide-react/dist/esm/icons/file-text";
import History from "lucide-react/dist/esm/icons/history";
import KeyRound from "lucide-react/dist/esm/icons/key-round";
import Loader2 from "lucide-react/dist/esm/icons/loader-2";
import Network from "lucide-react/dist/esm/icons/network";
import Play from "lucide-react/dist/esm/icons/play";
import RefreshCw from "lucide-react/dist/esm/icons/refresh-cw";
import Search from "lucide-react/dist/esm/icons/search";
import Send from "lucide-react/dist/esm/icons/send";
import Settings from "lucide-react/dist/esm/icons/settings";
import ShieldAlert from "lucide-react/dist/esm/icons/shield-alert";
import ShieldCheck from "lucide-react/dist/esm/icons/shield-check";
import Terminal from "lucide-react/dist/esm/icons/terminal";
import Wifi from "lucide-react/dist/esm/icons/wifi";

type Finding = { id: string; moduleId: string; category: string; title: string; summary: string; severity: "low" | "medium" | "high" | "critical"; confidence: number; sourceUrl?: string; data: Record<string, unknown> };
type StreamItem = { type: string; runId: string; moduleId?: string; message: string; data?: unknown; timestamp: string };
type ModuleCoverage = { moduleId: string; label: string; category: string; status: "completed" | "no-findings" | "failed"; findingCount: number; notices: string[]; error?: string };
type ReconResult = { target?: { normalized?: string; type?: string }; findings?: Finding[]; entities?: GraphNode[]; relationships?: GraphEdge[]; risk?: { score: number; level: string }; summary?: string; coverage?: ModuleCoverage[]; persistence?: { status: "saved" | "degraded"; warning?: string }; completedAt?: string };

const nav = ["Operations", "Findings", "Graph", "History", "Settings"] as const;
const severityClass = { low: "severity-low", medium: "severity-medium", high: "severity-high", critical: "severity-critical" };

function metricFrom(findings: Finding[], category: string) { return findings.filter(item => item.category === category).length; }

export default function Home() {
  const { user, loading, isAuthenticated, logout } = useAuth();
  const utils = trpc.useUtils();
  const [activeNav, setActiveNav] = useState<(typeof nav)[number]>("Operations");
  const [target, setTarget] = useState("");
  const [context, setContext] = useState("");
  const [dorkIntensity, setDorkIntensity] = useState<"focused" | "balanced" | "deep">("balanced");
  const [preferredModel, setPreferredModel] = useState("built-in");
  const [enabledModules, setEnabledModules] = useState<string[]>([]);
  const [stream, setStream] = useState<StreamItem[]>([]);
  const [moduleStates, setModuleStates] = useState<Record<string, "queued" | "started" | "completed" | "failed">>({});
  const [liveResult, setLiveResult] = useState<ReconResult | null>(null);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [compareRunId, setCompareRunId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<"all" | Finding["severity"]>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<Message[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [authWaitExceeded, setAuthWaitExceeded] = useState(false);
  const sourceRef = useRef<AbortController | null>(null);

  const modulesQuery = trpc.recon.modules.useQuery(undefined, { staleTime: 5 * 60_000 });
  const settingsQuery = trpc.settings.get.useQuery(undefined, { enabled: isAuthenticated });
  const historyQuery = trpc.recon.list.useQuery(undefined, { enabled: isAuthenticated, refetchOnWindowFocus: false });
  const selectedRunQuery = trpc.recon.get.useQuery({ runId: selectedHistoryId || "invalid" }, { enabled: Boolean(selectedHistoryId) });
  const compareQuery = trpc.recon.compare.useQuery({ olderRunId: compareRunId || "invalid", newerRunId: selectedHistoryId || "invalid" }, { enabled: Boolean(compareRunId && selectedHistoryId && compareRunId !== selectedHistoryId) });
  const chatMutation = trpc.ai.chat.useMutation();
  const saveSettings = trpc.settings.save.useMutation({ onSuccess: () => { toast.success("Recon preferences saved."); utils.settings.get.invalidate(); } });

  useEffect(() => { if (settingsQuery.data) { setDorkIntensity(settingsQuery.data.dorkIntensity); setEnabledModules(settingsQuery.data.enabledModules); setPreferredModel(settingsQuery.data.preferredModel); } }, [settingsQuery.data]);
  useEffect(() => () => sourceRef.current?.abort(), []);
  useEffect(() => { const timer = window.setTimeout(() => setAuthWaitExceeded(true), 1800); return () => window.clearTimeout(timer); }, []);

  const result = liveResult || (selectedRunQuery.data?.results as ReconResult | null) || null;
  const findings = result?.findings || [];
  const coverage = result?.coverage || [];
  const findingCategories = useMemo(() => Array.from(new Set(findings.map(item => item.category))).sort(), [findings]);
  const visibleFindings = useMemo(() => findings.filter(item => (severityFilter === "all" || item.severity === severityFilter) && (categoryFilter === "all" || item.category === categoryFilter)), [findings, severityFilter, categoryFilter]);
  const providerStatus = settingsQuery.data?.providerStatus;
  const moduleCards = useMemo(() => (modulesQuery.data || []).filter(module => enabledModules.length === 0 || enabledModules.includes(module.id)), [modulesQuery.data, enabledModules]);

  const startRecon = () => {
    const normalizedTarget = target.trim();
    if (!normalizedTarget) { toast.error("Enter a domain, IP, email, username, URL, organization, phone number, or ASN."); return; }
    if (!isAuthenticated) { toast.error("Sign in to launch and preserve a recon run."); startLogin(); return; }
    sourceRef.current?.abort(); setStream([]); setLiveResult(null); setSelectedHistoryId(null); setModuleStates({}); setIsRunning(true);
    const params = new URLSearchParams({ target: normalizedTarget, context, dorkIntensity, modules: enabledModules.join(",") });
    const controller = new AbortController(); sourceRef.current = controller;
    const accessToken = window.sessionStorage.getItem("manus-cookie");
    void (async () => {
      try {
        const response = await fetch(`/api/recon/stream?${params.toString()}`, { credentials: "include", signal: controller.signal, headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined });
        if (!response.ok || !response.body) throw new Error("The secure recon stream could not be opened.");
        const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
        while (!controller.signal.aborted) {
          const chunk = await reader.read(); if (chunk.done) break;
          buffer += decoder.decode(chunk.value, { stream: true }); const frames = buffer.split("\n\n"); buffer = frames.pop() || "";
          for (const frame of frames) {
            const raw = frame.split("\n").find(line => line.startsWith("data: "))?.slice(6); if (!raw) continue;
            try {
              const item = JSON.parse(raw) as StreamItem;
              setStream(previous => [...previous, item]);
              if (item.runId) setActiveRunId(item.runId);
              if (item.moduleId && ["queued", "started", "completed", "failed"].includes(item.type)) setModuleStates(previous => ({ ...previous, [item.moduleId!]: item.type as "queued" | "started" | "completed" | "failed" }));
              if (item.type === "run-completed") { setLiveResult(item.data as ReconResult); setIsRunning(false); utils.recon.list.invalidate(); toast.success("Recon run completed."); }
              if (item.type === "failed" && !item.moduleId) { setIsRunning(false); toast.error(item.message); }
            } catch { toast.error("A live recon event could not be decoded."); }
          }
        }
      } catch (error) { if (!controller.signal.aborted) { setIsRunning(false); toast.error(error instanceof Error ? error.message : "The recon stream ended unexpectedly."); } }
    })();
  };

  const sendChat = (content: string) => {
    const next = [...chatMessages, { role: "user" as const, content }]; setChatMessages(next);
    chatMutation.mutate({ messages: next.map(item => ({ role: item.role === "assistant" ? "assistant" as const : "user" as const, content: item.content })) }, { onSuccess: reply => setChatMessages(previous => [...previous, { role: "assistant", content: reply.content }]), onError: () => { toast.error("AI analysis is currently unavailable."); } });
  };

  const selectHistory = (runId: string) => { setSelectedHistoryId(runId); setLiveResult(null); setActiveNav("Findings"); };
  const rerun = (run: { target: string; context: string | null }) => { setTarget(run.target); setContext(run.context || ""); setActiveNav("Operations"); toast.message("Target loaded into the command bar."); };
  const exportResult = (format: "json" | "md" | "html") => {
    if (!result) { toast.error("Complete or open a recon run before exporting."); return; }
    const base = `recongpt-${result.target?.normalized || "report"}`.replace(/[^a-z0-9.-]/gi, "-");
    if (format === "json") downloadReport(`${base}.json`, "application/json", JSON.stringify(result, null, 2));
    if (format === "md") downloadReport(`${base}.md`, "text/markdown", markdownReport(result));
    if (format === "html") { const reportWindow = window.open("", "_blank"); if (reportWindow) { reportWindow.document.write(printableHtmlReport(result)); reportWindow.document.close(); reportWindow.focus(); reportWindow.print(); } else toast.error("Allow pop-ups to open the printable report."); }
  };

  if (loading && !authWaitExceeded) return <div className="boot-screen"><CircleDotDashed className="spin" /><span>Booting analyst workspace…</span></div>;

  return <main className="mission-shell">
    <aside className="mission-sidebar">
      <div className="brand"><span className="brand-mark"><Terminal size={18} /></span><div><strong>RECON<span>GPT</span></strong><small>intelligence station</small></div></div>
      <nav aria-label="Workspace sections">{nav.map(item => <button key={item} onClick={() => setActiveNav(item)} className={activeNav === item ? "nav-active" : ""}>{item === "Operations" ? <Activity size={17} /> : item === "Findings" ? <ShieldAlert size={17} /> : item === "Graph" ? <Network size={17} /> : item === "History" ? <History size={17} /> : <Settings size={17} />}<span>{item}</span>{item === "Operations" && isRunning ? <i className="pulse-dot" /> : null}</button>)}</nav>
      <div className="sidebar-status"><span><i className="online-dot" /> PASSIVE MODE</span><p>Evidence-first public intelligence. No active scanning or credential collection.</p></div>
      <div className="sidebar-user">{isAuthenticated ? <><span className="avatar">{user?.name?.slice(0, 1).toUpperCase() || "A"}</span><div><strong>{user?.name || "Analyst"}</strong><button onClick={() => logout()}>Sign out</button></div></> : <button className="signin-button" onClick={() => startLogin()}><KeyRound size={16} /> Sign in to operate</button>}</div>
    </aside>

    <section className="mission-main">
      <header className="topbar"><div><p className="eyebrow"><Wifi size={13} /> LIVE INTELLIGENCE WORKSPACE</p><h1>{activeNav === "Operations" ? "Mission control" : activeNav}</h1></div><div className="topbar-actions"><span className="clock">{new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}</span>{activeRunId ? <span className="run-id">RUN {activeRunId}</span> : null}</div></header>
      {activeNav === "Findings" && result ? <SourceCoverage coverage={coverage} persistence={result.persistence} findings={findings} /> : null}

      {activeNav === "Operations" ? <div className="workspace-grid">
        <section className="command-deck panel"><div className="panel-heading"><div><p className="eyebrow"><Command size={13} /> RECON COMMAND</p><h2>Launch a passive investigation</h2></div><span className="mode-badge">{isRunning ? "streaming" : "ready"}</span></div>
          <div className="terminal-bar"><span className="prompt">recon@station:~$</span><input aria-label="Recon target" value={target} onChange={event => setTarget(event.target.value)} onKeyDown={event => { if (event.key === "Enter") startRecon(); }} placeholder="target: domain, IP, email, username, URL, organization…" /><button onClick={startRecon} disabled={isRunning}>{isRunning ? <Loader2 className="spin" size={17} /> : <Play size={17} />}{isRunning ? "Running" : "Launch"}</button></div>
          <div className="command-options"><label>Context <input value={context} onChange={event => setContext(event.target.value)} placeholder="Optional authorized scope or analyst note" /></label><label>Research depth <select value={dorkIntensity} onChange={event => setDorkIntensity(event.target.value as typeof dorkIntensity)}><option value="focused">Focused</option><option value="balanced">Balanced</option><option value="deep">Deep</option></select></label></div>
          <div className="guardrail"><ShieldCheck size={16} /><span>Runs only use passive, public sources and third-party historical intelligence. Verify ownership and authorization before acting on results.</span></div>
        </section>
        <section className="chat-deck panel"><div className="panel-heading"><div><p className="eyebrow"><Bot size={13} /> NATURAL-LANGUAGE ANALYST</p><h2>Ask ReconGPT</h2></div><span className="ai-badge">AI</span></div><AIChatBox messages={chatMessages} onSendMessage={sendChat} isLoading={chatMutation.isPending} height="315px" className="mission-chat" placeholder="Ask about a finding or plan safe public research…" emptyStateMessage="Ask for an evidence-based analysis or safe reconnaissance plan." suggestedPrompts={["What is a good passive research plan for a domain?", "How should I validate a finding before escalation?"]} /></section>
        <section className="stream-deck panel"><div className="panel-heading"><div><p className="eyebrow"><Activity size={13} /> EVENT STREAM</p><h2>Live recon telemetry</h2></div><span className="stream-count">{stream.length} events</span></div><div className="stream-list">{stream.length === 0 ? <div className="stream-empty"><CircleDotDashed size={24} /><p>Live module progress will appear here through a persistent event stream.</p></div> : stream.slice().reverse().map((item, index) => <div className={`stream-row stream-${item.type}`} key={`${item.timestamp}-${index}`}><i /><div><strong>{item.moduleId?.replaceAll("-", " ") || "orchestrator"}</strong><p>{item.message}</p></div><time>{new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time></div>)}</div></section>
        <section className="module-deck panel"><div className="panel-heading"><div><p className="eyebrow"><CircleDotDashed size={13} /> MODULE GRID</p><h2>Collection progress</h2></div><span className="module-count">{moduleCards.length} enabled</span></div><div className="module-grid">{moduleCards.map(module => { const state = moduleStates[module.id] || "queued"; return <div className={`module-card state-${state}`} key={module.id}><i>{state === "completed" ? <Check size={13} /> : state === "started" ? <Loader2 className="spin" size={13} /> : <CircleDotDashed size={13} />}</i><div><strong>{module.label}</strong><span>{module.category}</span></div></div>; })}</div></section>
      </div> : null}

      {activeNav === "Findings" ? <section className="findings-page"><div className="metrics-row"><Metric label="Evidence score" value={result?.risk ? `${result.risk.score}/100` : "—"} tone={result?.risk?.level || "low"} /><Metric label="Verified findings" value={findings.length} tone="blue" /><Metric label="Infrastructure" value={metricFrom(findings, "Infrastructure") + metricFrom(findings, "Domain")} tone="green" /><Metric label="Threat signals" value={metricFrom(findings, "Threat Intelligence") + metricFrom(findings, "IP Intelligence")} tone="amber" /></div><section className="panel executive"><div><p className="eyebrow"><ShieldCheck size={13} /> AI EXECUTIVE ASSESSMENT</p><h2>{result?.target?.normalized || "Awaiting a recon run"}</h2></div><MarkdownContent content={result?.summary || "Run passive reconnaissance to receive an evidence-grounded assessment, severity score, and limitations."} /><div className="export-group"><button onClick={() => exportResult("md")}><FileText size={15} /> Markdown</button><button onClick={() => exportResult("json")}><FileCode2 size={15} /> JSON</button><button onClick={() => exportResult("html")}><Download size={15} /> Print HTML</button></div></section><section className="panel findings-table"><div className="panel-heading"><div><p className="eyebrow"><Search size={13} /> EVIDENCE EXPLORER</p><h2>Verified passive findings</h2></div><span>{visibleFindings.length}/{findings.length} records</span></div>{findings.length === 0 ? <div className="empty-findings">No evidence loaded. Complete a run or select one from recon history.</div> : <><div className="finding-filters"><label>Severity<select value={severityFilter} onChange={event => setSeverityFilter(event.target.value as typeof severityFilter)}><option value="all">All severities</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label><label>Category<select value={categoryFilter} onChange={event => setCategoryFilter(event.target.value)}><option value="all">All categories</option>{findingCategories.map(category => <option key={category} value={category}>{category}</option>)}</select></label><button onClick={() => { setSeverityFilter("all"); setCategoryFilter("all"); }}>Clear filters</button></div><div className="finding-list">{visibleFindings.length === 0 ? <div className="empty-findings">No findings match the active filters.</div> : visibleFindings.map(item => <article key={item.id} className={`finding-row ${expandedFindingId === item.id ? "finding-expanded" : ""}`}><span className={`severity ${severityClass[item.severity]}`}>{item.severity}</span><button className="finding-summary" onClick={() => setExpandedFindingId(previous => previous === item.id ? null : item.id)} aria-expanded={expandedFindingId === item.id}><p className="finding-category">{item.category} · {item.confidence}% confidence</p><h3>{item.title}</h3><p>{item.summary}</p></button>{item.sourceUrl ? <a href={item.sourceUrl} target="_blank" rel="noreferrer" aria-label={`Open evidence source for ${item.title}`}><ExternalLink size={17} /></a> : <span />}{expandedFindingId === item.id ? <div className="finding-detail"><strong>Evidence detail</strong><pre>{JSON.stringify(item.data, null, 2)}</pre></div> : null}</article>)}</div></>}</section></section> : null}

      {activeNav === "Graph" ? <ReconGraph nodes={result?.entities || []} edges={result?.relationships || []} /> : null}

      {activeNav === "History" ? <section className="history-page"><section className="panel"><div className="panel-heading"><div><p className="eyebrow"><History size={13} /> PERSISTED OPERATIONS</p><h2>Recon history & comparison</h2></div><button className="icon-button" onClick={() => historyQuery.refetch()} aria-label="Refresh history"><RefreshCw size={16} /></button></div><div className="history-list">{(historyQuery.data || []).length === 0 ? <div className="empty-findings">No previous recon runs are available for this analyst account.</div> : historyQuery.data?.map(run => <article key={run.id} className={`history-row ${selectedHistoryId === run.id ? "history-selected" : ""}`}><button onClick={() => selectHistory(run.id)}><span className="history-target">{run.target}</span><span>{run.targetType} · {new Date(run.startedAt).toLocaleString()}</span></button><span className={`severity ${severityClass[run.riskLevel]}`}>{run.riskScore}/100</span><button className="rerun-button" onClick={() => rerun(run)}><RefreshCw size={14} /> Re-run</button></article>)}</div></section>{selectedHistoryId ? <section className="panel compare-panel"><div className="panel-heading"><div><p className="eyebrow"><ChevronRight size={13} /> DELTA VIEW</p><h2>Compare stored runs</h2></div></div><label>Compare selected run with <select value={compareRunId || ""} onChange={event => setCompareRunId(event.target.value || null)}><option value="">Choose an earlier run</option>{historyQuery.data?.filter(run => run.id !== selectedHistoryId).map(run => <option key={run.id} value={run.id}>{run.target} — {new Date(run.startedAt).toLocaleDateString()}</option>)}</select></label>{compareQuery.data ? <div className="compare-grid"><div><strong>+ {compareQuery.data.added.length}</strong><span>new finding families</span></div><div><strong>− {compareQuery.data.removed.length}</strong><span>removed finding families</span></div><div><strong>{compareQuery.data.scoreChange > 0 ? "+" : ""}{compareQuery.data.scoreChange}</strong><span>score change</span></div></div> : <p className="muted">Select another stored run to compare title-level finding differences and score movement.</p>}</section> : null}</section> : null}

      {activeNav === "Settings" ? <section className="settings-page"><section className="panel"><div className="panel-heading"><div><p className="eyebrow"><Settings size={13} /> ANALYST CONTROL PLANE</p><h2>Collection preferences</h2></div><button onClick={() => saveSettings.mutate({ enabledModules, dorkIntensity, preferredModel })} disabled={saveSettings.isPending}>{saveSettings.isPending ? <Loader2 className="spin" size={15} /> : <Check size={15} />} Save settings</button></div><div className="setting-section"><h3>Provider vault</h3><p>Provider credentials remain server-only. Status never exposes full keys or shows them in browser-delivered source.</p><div className="provider-grid">{Object.entries(providerStatus || {}).map(([name, configured]) => <div className={`provider-card ${configured ? "provider-ready" : "provider-pending"}`} key={name}><span>{configured ? <Check size={15} /> : <KeyRound size={15} />}</span><div><strong>{name.replace(/([A-Z])/g, " $1")}</strong><small>{configured ? "server vault configured" : name === "builtInAnalysis" ? "platform analysis available" : "secure key needed"}</small></div></div>)}</div></div><div className="setting-section"><h3>Analyst model</h3><p>Select the platform model or an optional server-vault OpenAI/Groq key. External choices remain unavailable until a valid external key is configured.</p><select value={preferredModel} onChange={event => setPreferredModel(event.target.value)}><option value="built-in">Built-in analyst model</option><option value="external:openai:gpt-4o-mini" disabled={!providerStatus?.externalLlm}>OpenAI · GPT-4o mini</option><option value="external:groq:llama-3.3-70b-versatile" disabled={!providerStatus?.externalLlm}>Groq · Llama 3.3 70B</option></select></div><div className="setting-section"><h3>Enabled modules</h3><p>Activate only the passive collection modules appropriate for the engagement scope.</p><div className="toggle-grid">{(modulesQuery.data || []).map(module => <label key={module.id} className="module-toggle"><input type="checkbox" checked={enabledModules.includes(module.id)} onChange={event => setEnabledModules(previous => event.target.checked ? [...previous, module.id] : previous.filter(id => id !== module.id))} /><span><strong>{module.label}</strong><small>{module.category}</small></span></label>)}</div></div><div className="setting-section"><h3>Research-query intensity</h3><div className="intensity-set">{(["focused", "balanced", "deep"] as const).map(level => <button key={level} className={dorkIntensity === level ? "intensity-active" : ""} onClick={() => setDorkIntensity(level)}><strong>{level}</strong><span>{level === "focused" ? "minimal public pivots" : level === "balanced" ? "standard research set" : "expanded public pivots"}</span></button>)}</div></div></section></section> : null}
    </section>
  </main>;
}

function Metric({ label, value, tone }: { label: string; value: string | number; tone: string }) { return <div className={`metric metric-${tone}`}><span>{label}</span><strong>{value}</strong></div>; }

function SourceCoverage({ coverage, persistence, findings }: { coverage: ModuleCoverage[]; persistence?: ReconResult["persistence"]; findings: Finding[] }) {
  const completed = coverage.filter(item => item.status === "completed").length;
  const empty = coverage.filter(item => item.status === "no-findings").length;
  const failed = coverage.filter(item => item.status === "failed").length;
  const gaps = coverage.filter(item => item.status !== "completed" || item.notices.length > 0);
  const crawl = findings.find(item => item.moduleId === "public-web-crawl")?.data as Record<string, unknown> | undefined;
  const crawlPolicy = crawl?.crawlPolicy as Record<string, unknown> | undefined;
  const reviewedPages = Array.isArray(crawl?.pages) ? crawl.pages.length : 0;
  const pageBudget = typeof crawlPolicy?.maxPages === "number" ? crawlPolicy.maxPages : 0;
  const maxDepth = typeof crawlPolicy?.maxDepth === "number" ? crawlPolicy.maxDepth : 0;
  const skipped = typeof crawl?.skippedCount === "number" ? crawl.skippedCount : 0;
  const search = findings.find(item => item.moduleId === "public-search")?.data as Record<string, unknown> | undefined;
  const searchResults = Array.isArray(search?.results) ? search.results.length : 0;
  return <section className="source-coverage" aria-label="Collection source coverage"><div><p className="eyebrow"><Wifi size={13} /> SOURCE COVERAGE</p><strong>{completed}/{coverage.length} sources returned evidence</strong><span>{empty} no-result · {failed} unavailable</span></div><p>{gaps.length ? gaps.slice(0, 3).map(item => `${item.label}: ${item.status === "failed" ? item.error || "unavailable" : item.notices.join(" ") || "no evidence returned"}`).join(" | ") : "All selected modules returned evidence. Public-source results remain point-in-time observations, not proof of absence or exhaustive coverage."}</p>{crawl ? <p className="source-crawl"><strong>PUBLIC CRAWL</strong> {reviewedPages}/{pageBudget || "—"} same-origin HTML page(s) reviewed at depth {maxDepth}; {skipped} URL(s) skipped by robots, scope, or response policy. No authentication, forms, private networks, or cross-origin traversal.</p> : null}{search ? <p className="source-crawl"><strong>FREE SEARCH</strong> {searchResults} structured public result(s) received; linked analyst pivots cover DuckDuckGo, Bing, and Google without screen-scraping search result pages.</p> : null}{persistence?.status === "degraded" ? <p className="source-warning"><ShieldAlert size={14} /> Live result delivered; run-history storage was degraded. {persistence.warning || "Rerun if a persisted copy is required."}</p> : null}</section>;
}
