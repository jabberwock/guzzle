import type { FunctionSignature } from "../../store/session";

interface FunctionBannerProps {
  signature: FunctionSignature | null;
  loading: boolean;
  onFuzz: () => void;
}

export default function FunctionBanner({ signature, loading, onFuzz }: FunctionBannerProps) {
  if (loading) {
    return (
      <div className="border-t border-[#30363d] bg-[#161b22] px-4 py-3 flex items-center gap-3">
        <div className="w-4 h-4 border-2 border-[#58a6ff] border-t-transparent rounded-full animate-spin" />
        <span className="text-sm text-[#8b949e]">Detecting function…</span>
      </div>
    );
  }

  if (!signature) {
    return (
      <div className="border-t border-[#30363d] bg-[#161b22] px-4 py-3">
        <span className="text-sm text-[#8b949e]">
          Click inside a function to detect its signature.
        </span>
      </div>
    );
  }

  const paramStr = signature.params
    .map((p) => `${p.type_name} ${p.param_name}`.trim())
    .join(", ");

  return (
    <div className="border-t border-[#30363d] bg-[#161b22] px-4 py-3 flex items-center justify-between gap-4">
      <div className="flex-1 min-w-0">
        <p className="text-[11px] text-[#8b949e] uppercase tracking-wider mb-1">
          Detected function · lines {signature.start_line}–{signature.end_line}
        </p>
        <code className="text-sm text-[#e6edf3] font-mono truncate block">
          <span className="text-[#79c0ff]">{signature.return_type}</span>{" "}
          <span className="text-[#d2a8ff] font-bold">{signature.name}</span>
          <span className="text-[#e6edf3]">(</span>
          <span className="text-[#ffa657]">{paramStr}</span>
          <span className="text-[#e6edf3]">)</span>
        </code>
      </div>
      <button
        onClick={onFuzz}
        className="shrink-0 px-4 py-2 bg-[#238636] hover:bg-[#2ea043] text-white text-sm font-medium rounded-md transition-colors flex items-center gap-2"
      >
        <span>⚡</span>
        Fuzz this function →
      </button>
    </div>
  );
}
