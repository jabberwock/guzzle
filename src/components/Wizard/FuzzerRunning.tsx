import { memo, useEffect, useRef, useState } from "react";
import { useSession } from "../../store/session";
import { startFuzzer, stopFuzzer } from "../../lib/tauri";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import Terminal from "../shared/Terminal";
import type { FuzzerStats } from "../../store/session";

interface Props {
  onBack: () => void;
  onNext: () => void;
}

const StatBadge = memo(function StatBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#21262d] rounded-lg px-4 py-3 text-center">
      <p className="text-[10px] text-[#8b949e] uppercase tracking-wider">{label}</p>
      <p className="text-lg font-bold text-[#e6edf3] mt-0.5">{value}</p>
    </div>
  );
});

function fmtTime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function FuzzerRunning({ onBack, onNext }: Props) {
  const {
    compiledBinaryPath,
    filePath,
    fuzzerPid,
    fuzzerOutput,
    fuzzerStats,
    crashes,
    setFuzzerPid,
    appendFuzzerOutput,
    clearFuzzerOutput,
    setFuzzerStats,
    setCrashes,
  } = useSession();

  const startedRef = useRef(false);
  const [running, setRunning] = useState(true);
  const [seedDir, setSeedDir] = useState<string | null>(null);

  const defaultCorpusDir = filePath
    ? filePath.replace(/\/[^/]+$/, "") + "/.guzzle/corpus"
    : "/tmp/guzzle_corpus";

  const corpusDir = seedDir ?? defaultCorpusDir;

  const startFuzzing = async () => {
    if (!compiledBinaryPath) return;
    clearFuzzerOutput();
    setCrashes([]);
    setFuzzerStats(null);
    setRunning(true);

    let unlistenOutput: (() => void) | null = null;
    let unlistenCrash: (() => void) | null = null;
    let unlistenStats: (() => void) | null = null;
    let unlistenStopped: (() => void) | null = null;

    // Buffer lines and flush every 150ms to avoid hammering React with
    // thousands of state updates per second from libFuzzer's output
    let outputBuffer: string[] = [];
    const flushInterval = setInterval(() => {
      if (outputBuffer.length === 0) return;
      outputBuffer.forEach(appendFuzzerOutput);
      outputBuffer = [];
    }, 150);

    unlistenOutput = await listen<string>("fuzzer_output", (e) => {
      outputBuffer.push(e.payload);
    });
    unlistenCrash = await listen<{ path: string; size: number; preview_bytes: number[] }>(
      "fuzzer_crash",
      (e) => {
        setCrashes([...crashes, e.payload]);
      }
    );
    let lastStats = 0;
    unlistenStats = await listen<FuzzerStats>("fuzzer_stats", (e) => {
      const now = Date.now();
      if (now - lastStats < 500) return;
      lastStats = now;
      setFuzzerStats(e.payload);
    });
    unlistenStopped = await listen("fuzzer_stopped", () => {
      clearInterval(flushInterval);
      outputBuffer.forEach(appendFuzzerOutput);
      outputBuffer = [];
      setRunning(false);
      setFuzzerPid(null);
      unlistenOutput?.();
      unlistenCrash?.();
      unlistenStats?.();
      unlistenStopped?.();
    });

    try {
      const pid = await startFuzzer({
        binary: compiledBinaryPath,
        corpus_dir: corpusDir,
        max_total_time: 0,
        jobs: 1,
      });
      setFuzzerPid(pid);
    } catch (e) {
      appendFuzzerOutput(`Error starting fuzzer: ${String(e)}`);
      setRunning(false);
    }
  };

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    startFuzzing();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleStop = async () => {
    if (fuzzerPid) {
      await stopFuzzer(fuzzerPid);
    }
    setRunning(false);
    setFuzzerPid(null);
    onNext();
  };

  const pickSeedDir = async () => {
    const dir = await open({ directory: true, multiple: false });
    if (typeof dir === "string") setSeedDir(dir);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[#e6edf3]">Fuzzer Running</h2>
          <p className="text-sm text-[#8b949e] mt-1">
            Corpus: <code className="text-xs font-mono text-[#8b949e]">{corpusDir}</code>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={pickSeedDir}
            className="text-xs text-[#58a6ff] hover:underline"
          >
            + Seed corpus
          </button>
          {running ? (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-[#3fb950] rounded-full animate-pulse" />
              <span className="text-xs text-[#3fb950] font-medium">Running</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-[#8b949e] rounded-full" />
              <span className="text-xs text-[#8b949e] font-medium">Stopped</span>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        <StatBadge label="Execs/sec" value={fuzzerStats ? fuzzerStats.execs_per_sec.toLocaleString() : "—"} />
        <StatBadge label="Coverage"  value={fuzzerStats ? `${fuzzerStats.coverage}` : "—"} />
        <StatBadge label="Corpus"    value={fuzzerStats ? `${fuzzerStats.corpus_size}` : "—"} />
        <StatBadge label="Run Time"  value={fuzzerStats ? fmtTime(fuzzerStats.run_time_secs) : "—"} />
      </div>

      <div className={`rounded-md p-3 text-sm flex items-center justify-between transition-colors ${
        crashes.length > 0
          ? "bg-[#3d1414] border border-[#f85149] text-[#f85149]"
          : "bg-transparent border border-transparent text-transparent"
      }`}>
        <span>🐛 {crashes.length} crash{crashes.length !== 1 ? "es" : ""} found!</span>
        <button onClick={crashes.length > 0 ? onNext : undefined} className="underline text-xs">View results →</button>
      </div>

      <Terminal lines={fuzzerOutput} />

      <div className="flex justify-between">
        <button
          onClick={onBack}
          disabled={running}
          className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] disabled:opacity-40 text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
        >
          ← Back
        </button>
        <div className="flex gap-2">
          {!running && (
            <button
              onClick={onNext}
              className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#e6edf3] text-sm font-medium rounded-md transition-colors"
            >
              View Results →
            </button>
          )}
          {running && (
            <button
              onClick={handleStop}
              className="px-4 py-2 bg-[#da3633] hover:bg-[#b91c1c] text-white text-sm font-medium rounded-md transition-colors"
            >
              ■ Stop & View Results
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
