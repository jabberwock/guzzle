import { useEffect, useState } from "react";
import { useSession } from "../../store/session";
import { checkToolchain, checkToolchainAt } from "../../lib/tauri";

interface CheckRowProps {
  label: string;
  value: string | boolean | null;
  ok: boolean | null;
  editable?: boolean;
  onEdit?: (val: string) => void;
}

function CheckRow({ label, value, ok, editable, onEdit }: CheckRowProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");

  const startEdit = () => {
    setDraft(typeof value === "string" ? value : "");
    setEditing(true);
  };

  const commit = () => {
    setEditing(false);
    onEdit?.(draft.trim());
  };

  return (
    <div className="flex items-center justify-between py-2 border-b border-[#21262d] last:border-0 gap-3">
      <span className="text-sm text-[#e6edf3] shrink-0">{label}</span>
      <div className="flex items-center gap-2 min-w-0 flex-1 justify-end">
        {editing ? (
          <>
            <input
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") commit(); if (e.key === "Escape") setEditing(false); }}
              className="flex-1 min-w-0 px-2 py-0.5 bg-[#0d1117] border border-[#58a6ff] rounded text-sm font-mono text-[#e6edf3] outline-none"
            />
            <button onClick={commit} className="text-xs px-2 py-0.5 bg-[#238636] hover:bg-[#2ea043] text-white rounded">OK</button>
            <button onClick={() => setEditing(false)} className="text-xs px-2 py-0.5 bg-[#21262d] hover:bg-[#30363d] text-[#8b949e] rounded">✕</button>
          </>
        ) : (
          <>
            <span className="text-sm font-mono text-[#8b949e] truncate max-w-xs">
              {typeof value === "boolean" ? (value ? "yes" : "no") : value ?? "—"}
            </span>
            {editable && (
              <button
                onClick={startEdit}
                title="Edit path"
                className="text-[#8b949e] hover:text-[#58a6ff] shrink-0 text-xs px-1"
              >
                ✎
              </button>
            )}
            {ok === null ? (
              <div className="w-4 h-4 border-2 border-[#8b949e] border-t-transparent rounded-full animate-spin shrink-0" />
            ) : ok ? (
              <span className="text-[#3fb950] text-lg shrink-0">✓</span>
            ) : (
              <span className="text-[#f85149] text-lg shrink-0">✗</span>
            )}
          </>
        )}
      </div>
    </div>
  );
}

interface Props {
  onNext: () => void;
  onClose: () => void;
}

export default function ToolchainCheck({ onNext, onClose }: Props) {
  const { toolchainInfo, setToolchainInfo, compileSettings, updateCompileSettings } = useSession();
  const [loading, setLoading] = useState(!toolchainInfo);
  const [error, setError] = useState<string | null>(null);
  const [rechecking, setRechecking] = useState(false);

  useEffect(() => {
    if (toolchainInfo) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const info = await checkToolchain();
        if (!cancelled) {
          setToolchainInfo(info);
          // If auto-detected path differs from any saved override, clear the override
          // so the display stays accurate.
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(String(e));
          setLoading(false);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [toolchainInfo, setToolchainInfo]);

  // Auto-advance if all checks pass
  useEffect(() => {
    if (toolchainInfo?.clang_path && toolchainInfo.fuzzer_supported && toolchainInfo.asan_supported) {
      const t = setTimeout(onNext, 1200);
      return () => clearTimeout(t);
    }
  }, [toolchainInfo, onNext]);

  const handleEditPath = async (newPath: string) => {
    if (!newPath) return;
    updateCompileSettings({ clang_override: newPath });
    setRechecking(true);
    setError(null);
    try {
      const info = await checkToolchainAt(newPath);
      setToolchainInfo(info);
    } catch (e) {
      setError(String(e));
    } finally {
      setRechecking(false);
    }
  };

  const resetAutoDetect = async () => {
    updateCompileSettings({ clang_override: "" });
    setToolchainInfo(null as any);
    setError(null);
    setLoading(true);
    try {
      const info = await checkToolchain();
      setToolchainInfo(info);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const allGood = toolchainInfo?.clang_path && toolchainInfo.fuzzer_supported && toolchainInfo.asan_supported;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-lg font-semibold text-[#e6edf3]">Toolchain Check</h2>
        <p className="text-sm text-[#8b949e] mt-1">
          Verifying that clang and libFuzzer are available on your system.
        </p>
      </div>

      <div className="bg-[#21262d] rounded-lg p-4">
        {loading ? (
          <div className="flex items-center gap-3 py-4">
            <div className="w-5 h-5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-[#8b949e]">Checking toolchain…</span>
          </div>
        ) : rechecking ? (
          <div className="flex items-center gap-3 py-4">
            <div className="w-5 h-5 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-[#8b949e]">Re-checking…</span>
          </div>
        ) : error ? (
          <div className="text-[#f85149] text-sm">{error}</div>
        ) : toolchainInfo ? (
          <>
            <CheckRow
              label="clang path"
              value={toolchainInfo.clang_path || "not found"}
              ok={!!toolchainInfo.clang_path}
              editable
              onEdit={handleEditPath}
            />
            <CheckRow
              label="clang version"
              value={toolchainInfo.version || "unknown"}
              ok={!!toolchainInfo.version}
            />
            <CheckRow
              label="-fsanitize=fuzzer"
              value={toolchainInfo.fuzzer_supported}
              ok={toolchainInfo.fuzzer_supported}
            />
            <CheckRow
              label="-fsanitize=address"
              value={toolchainInfo.asan_supported}
              ok={toolchainInfo.asan_supported}
            />
          </>
        ) : null}
      </div>

      {!loading && !allGood && toolchainInfo && (
        <div className="bg-[#3d1f00] border border-[#d29922] rounded-lg p-4 text-sm text-[#e6edf3]">
          <p className="font-semibold text-[#d29922] mb-2">⚠ Toolchain issue detected</p>
          {!toolchainInfo.clang_path && (
            <p className="mb-1">
              <strong>clang not found.</strong> Install LLVM:{" "}
              <span className="font-mono text-[#58a6ff]">brew install llvm</span> (macOS) or{" "}
              <span className="font-mono text-[#58a6ff]">apt install clang llvm-dev libclang-rt-dev</span> (Linux)
            </p>
          )}
          {toolchainInfo.clang_path && !toolchainInfo.fuzzer_supported && (
            <p className="mb-1">
              <strong>libFuzzer not supported.</strong> Click the ✎ pencil next to the path and enter a versioned clang like{" "}
              <span className="font-mono text-[#58a6ff]">/usr/bin/clang++-16</span>.
            </p>
          )}
        </div>
      )}

      {!loading && allGood && (
        <div className="bg-[#0d2818] border border-[#3fb950] rounded-lg p-3 text-sm text-[#3fb950]">
          ✓ All checks passed — advancing automatically…
        </div>
      )}

      <div className="flex justify-between">
        <div className="flex gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#8b949e] text-sm font-medium rounded-md transition-colors"
          >
            ← Close
          </button>
          {compileSettings.clang_override && (
            <button
              onClick={resetAutoDetect}
              className="px-4 py-2 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-[#8b949e] text-sm font-medium rounded-md transition-colors"
            >
              Auto-detect
            </button>
          )}
        </div>
        <button
          onClick={onNext}
          disabled={loading || !allGood}
          className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
        >
          Next →
        </button>
      </div>
    </div>
  );
}
