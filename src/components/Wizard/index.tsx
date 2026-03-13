import { useSession } from "../../store/session";
import StepIndicator from "../shared/StepIndicator";
import ToolchainCheck from "./ToolchainCheck";
import HarnessEditor from "./HarnessEditor";
import CompileSettings from "./CompileSettings";
import FuzzerRunning from "./FuzzerRunning";
import Results from "./Results";

export default function Wizard() {
  const { wizardOpen, wizardStep, setWizardStep, closeWizard, functionSignature } = useSession();

  if (!wizardOpen || !functionSignature) return null;

  const goTo = (step: typeof wizardStep) => setWizardStep(step);

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]"
        style={{ minHeight: 520 }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d]">
          <div className="flex items-center gap-3">
            <span className="text-lg">⚡</span>
            <span className="font-semibold text-[#e6edf3]">Fuzz Wizard</span>
            <span className="text-sm text-[#8b949e]">— {functionSignature.name}()</span>
          </div>
          <button
            onClick={closeWizard}
            className="text-[#8b949e] hover:text-[#e6edf3] text-xl leading-none transition-colors"
          >
            ×
          </button>
        </div>

        {/* Step indicator */}
        <div className="px-6 pt-5 pb-3 flex justify-center">
          <StepIndicator current={wizardStep} onGoTo={goTo} />
        </div>

        {/* Step content */}
        <div className="flex-1 overflow-y-auto px-6 pb-6">
          {wizardStep === "toolchain" && (
            <ToolchainCheck onNext={() => goTo("harness")} onClose={closeWizard} />
          )}
          {wizardStep === "harness" && (
            <HarnessEditor
              onBack={() => goTo("toolchain")}
              onNext={() => goTo("compile")}
            />
          )}
          {wizardStep === "compile" && (
            <CompileSettings
              onBack={() => goTo("harness")}
              onNext={() => goTo("running")}
            />
          )}
          {wizardStep === "running" && (
            <FuzzerRunning
              onBack={() => goTo("compile")}
              onNext={() => goTo("results")}
            />
          )}
          {wizardStep === "results" && (
            <Results onClose={closeWizard} />
          )}
        </div>
      </div>
    </div>
  );
}
