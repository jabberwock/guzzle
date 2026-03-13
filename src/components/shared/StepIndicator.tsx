import type { WizardStep } from "../../store/session";

const STEPS: { key: WizardStep; label: string }[] = [
  { key: "toolchain", label: "Toolchain" },
  { key: "harness", label: "Harness" },
  { key: "compile", label: "Compile" },
  { key: "running", label: "Fuzzing" },
  { key: "results", label: "Results" },
];

interface StepIndicatorProps {
  current: WizardStep;
  onGoTo?: (step: WizardStep) => void;
}

export default function StepIndicator({ current, onGoTo }: StepIndicatorProps) {
  const currentIdx = STEPS.findIndex((s) => s.key === current);

  return (
    <div className="flex items-center gap-0">
      {STEPS.map((step, idx) => {
        const done = idx < currentIdx;
        const active = idx === currentIdx;
        const clickable = done && onGoTo;
        return (
          <div key={step.key} className="flex items-center">
            <div className="flex flex-col items-center">
              <div
                onClick={() => clickable && onGoTo(step.key)}
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all ${
                  done
                    ? "bg-[#3fb950] border-[#3fb950] text-black"
                    : active
                    ? "bg-transparent border-[#58a6ff] text-[#58a6ff]"
                    : "bg-transparent border-[#30363d] text-[#8b949e]"
                } ${clickable ? "cursor-pointer hover:opacity-75" : ""}`}
              >
                {done ? "✓" : idx + 1}
              </div>
              <span
                onClick={() => clickable && onGoTo(step.key)}
                className={`mt-1 text-[10px] font-medium ${
                  active ? "text-[#58a6ff]" : done ? "text-[#3fb950]" : "text-[#8b949e]"
                } ${clickable ? "cursor-pointer hover:opacity-75" : ""}`}
              >
                {step.label}
              </span>
            </div>
            {idx < STEPS.length - 1 && (
              <div
                className={`h-0.5 w-10 mx-1 mb-4 transition-all ${
                  done ? "bg-[#3fb950]" : "bg-[#30363d]"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
