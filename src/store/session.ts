import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface FunctionSignature {
  name: string;
  return_type: string;
  params: Array<{ type_name: string; param_name: string }>;
  start_line: number;
  end_line: number;
}

export interface ToolchainInfo {
  clang_path: string;
  version: string;
  fuzzer_supported: boolean;
  fuzzer_error: string;
  asan_supported: boolean;
}

export interface CompileSettings {
  sanitizers: string[];
  includes: string[];
  library_files: string[];
  extra_flags: string;
  out_path: string;
  clang_override: string;
}

export interface CrashFile {
  path: string;
  size: number;
  preview_bytes: number[];
  modified_secs: number;
}

export interface FuzzerStats {
  execs_per_sec: number;
  coverage: number;
  corpus_size: number;
  run_time_secs: number;
  total_execs: number;
}

export type ApiFormat = "openai" | "anthropic";

export interface AiProvider {
  name: string;
  base_url: string;
  model: string;
  api_key: string;
  format: ApiFormat;
}

export const PRESET_PROVIDERS: AiProvider[] = [
  {
    name: "deepseek",
    base_url: "https://api.deepseek.com",
    model: "deepseek-chat",
    api_key: "",
    format: "openai",
  },
  {
    name: "ollama",
    base_url: "http://localhost:11434",
    model: "llama3",
    api_key: "",
    format: "openai",
  },
  {
    name: "claude",
    base_url: "https://api.anthropic.com",
    model: "claude-sonnet-4-6",
    api_key: "",
    format: "anthropic",
  },
  {
    name: "openai",
    base_url: "https://api.openai.com",
    model: "gpt-4o",
    api_key: "",
    format: "openai",
  },
];

export type WizardStep =
  | "toolchain"
  | "harness"
  | "compile"
  | "running"
  | "results";

interface SessionState {
  // File & source
  filePath: string | null;
  fileContent: string | null;
  recentFiles: string[];

  // Selected function
  selectedLine: number | null;
  functionSignature: FunctionSignature | null;

  // Wizard
  wizardOpen: boolean;
  wizardStep: WizardStep;

  // Toolchain
  toolchainInfo: ToolchainInfo | null;

  // Harness
  harnessSource: string;
  harnessGenerating: boolean;

  // Compile
  compileSettings: CompileSettings;
  compiledBinaryPath: string | null;
  compileLog: string[];

  // Fuzzer
  fuzzerPid: number | null;
  fuzzerOutput: string[];
  fuzzerStats: FuzzerStats | null;
  crashes: CrashFile[];

  // AI provider
  aiProvider: AiProvider;

  // Actions
  setFilePath: (path: string, content: string) => void;
  addRecentFile: (path: string) => void;
  setSelectedLine: (line: number | null) => void;
  setFunctionSignature: (sig: FunctionSignature | null) => void;
  openWizard: () => void;
  closeWizard: () => void;
  setWizardStep: (step: WizardStep) => void;
  setToolchainInfo: (info: ToolchainInfo) => void;
  setHarnessSource: (src: string) => void;
  setHarnessGenerating: (v: boolean) => void;
  updateCompileSettings: (s: Partial<CompileSettings>) => void;
  setCompiledBinaryPath: (p: string | null) => void;
  appendCompileLog: (line: string) => void;
  clearCompileLog: () => void;
  setFuzzerPid: (pid: number | null) => void;
  appendFuzzerOutput: (line: string) => void;
  clearFuzzerOutput: () => void;
  setFuzzerStats: (stats: FuzzerStats | null) => void;
  setCrashes: (crashes: CrashFile[]) => void;
  setAiProvider: (provider: AiProvider) => void;
}

export const useSession = create<SessionState>()(persist((set) => ({
  filePath: null,
  fileContent: null,
  recentFiles: [],
  selectedLine: null,
  functionSignature: null,
  wizardOpen: false,
  wizardStep: "toolchain",
  toolchainInfo: null,
  harnessSource: "",
  harnessGenerating: false,
  compileSettings: {
    sanitizers: ["fuzzer", "address"],
    includes: [],
    library_files: [],
    extra_flags: "",
    out_path: "",
    clang_override: "",
  },
  compiledBinaryPath: null,
  compileLog: [],
  fuzzerPid: null,
  fuzzerOutput: [],
  fuzzerStats: null,
  crashes: [],
  aiProvider: PRESET_PROVIDERS[0], // DeepSeek by default

  setFilePath: (path, content) =>
    set({ filePath: path, fileContent: content, selectedLine: null, functionSignature: null }),
  addRecentFile: (path) =>
    set((s) => ({
      recentFiles: [path, ...s.recentFiles.filter((f) => f !== path)].slice(0, 10),
    })),
  setSelectedLine: (line) => set({ selectedLine: line }),
  setFunctionSignature: (sig) => set({ functionSignature: sig }),
  openWizard: () => set((s) => {
    if (s.wizardOpen) {
      console.warn("[guzzle] openWizard() called while wizard already open — ignoring", new Error().stack);
      return {};
    }
    console.log("[guzzle] openWizard()");
    return {
      wizardOpen: true,
      wizardStep: "toolchain",
      compileLog: [],
      fuzzerOutput: [],
      fuzzerStats: null,
      crashes: [],
      compiledBinaryPath: null,
    };
  }),
  closeWizard: () => {
    console.log("[guzzle] closeWizard()", new Error().stack);
    set({ wizardOpen: false });
  },
  setWizardStep: (step) => {
    console.log("[guzzle] setWizardStep()", step);
    set({ wizardStep: step });
  },
  setToolchainInfo: (info) => set({ toolchainInfo: info }),
  setHarnessSource: (src) => set({ harnessSource: src }),
  setHarnessGenerating: (v) => set({ harnessGenerating: v }),
  updateCompileSettings: (s) =>
    set((prev) => ({ compileSettings: { ...prev.compileSettings, ...s } })),
  setCompiledBinaryPath: (p) => set({ compiledBinaryPath: p }),
  appendCompileLog: (line) =>
    set((s) => ({ compileLog: [...s.compileLog, line] })),
  clearCompileLog: () => set({ compileLog: [] }),
  setFuzzerPid: (pid) => set({ fuzzerPid: pid }),
  appendFuzzerOutput: (line) =>
    set((s) => ({ fuzzerOutput: [...s.fuzzerOutput.slice(-500), line] })),
  clearFuzzerOutput: () => set({ fuzzerOutput: [] }),
  setFuzzerStats: (stats) => set({ fuzzerStats: stats ?? null }),
  setCrashes: (crashes) => set({ crashes }),
  setAiProvider: (provider) => set({ aiProvider: provider }),
}), {
  name: "guzzle-session",
  // Only persist settings that are painful to re-enter — not transient runtime state
  partialize: (state) => ({
    recentFiles: state.recentFiles,
    compileSettings: state.compileSettings,
    // Persist provider config but not the api_key — that lives in the OS keychain
    aiProvider: { ...state.aiProvider, api_key: "" },
  }),
}));
