import { useEffect, useState } from "react";
import { useSession } from "../../store/session";
import { checkToolchain } from "../../lib/tauri";

interface CheckRowProps {
  label: string;
  value: string | boolean | null;
  ok: boolean | null;
}

function CheckRow({ label, value, ok }: CheckRowProps) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-[#21262d] last:border-0">
      <span className="text-sm text-[#e6edf3]">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm font-mono text-[#8b949e] max-w-xs truncate">
          {typeof value === "boolean" ? (value ? "yes" : "no") : value ?? "—"}
        </span>
        {ok === null ? (
          <div className="w-4 h-4 border-2 border-[#8b949e] border-t-transparent rounded-full animate-spin" />
        ) : ok ? (
          <span className="text-[#3fb950] text-lg">✓</span>
        ) : (
          <span className="text-[#f85149] text-lg">✗</span>
        )}
      </div>
    </div>
  );
}

interface Props {
  onNext: () => void;
}

export default function ToolchainCheck({ onNext }: Props) {
  const { toolchainInfo, setToolchainInfo } = useSession();
  const [loading, setLoading] = useState(!toolchainInfo);
  const [error, setError] = useState<string | null>(null);

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
        ) : error ? (
          <div className="text-[#f85149] text-sm">{error}</div>
        ) : toolchainInfo ? (
          <>
            <CheckRow
              label="clang path"
              value={toolchainInfo.clang_path || "not found"}
              ok={!!toolchainInfo.clang_path}
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
              <span className="font-mono text-[#58a6ff]">apt install clang</span> (Linux) or download from{" "}
              <span className="font-mono text-[#58a6ff]">llvm.org/releases</span> (Windows).
            </p>
          )}
          {toolchainInfo.clang_path && !toolchainInfo.fuzzer_supported && (
            <p className="mb-1">
              <strong>libFuzzer not supported.</strong> Your clang may lack fuzzer runtime. On macOS use{" "}
              <span className="font-mono text-[#58a6ff]">brew install llvm</span> and ensure LLVM clang is in PATH (not Apple clang).
            </p>
          )}
        </div>
      )}

      {!loading && allGood && (
        <div className="bg-[#0d2818] border border-[#3fb950] rounded-lg p-3 text-sm text-[#3fb950]">
          ✓ All checks passed — advancing automatically…
        </div>
      )}

      <div className="flex justify-end">
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
