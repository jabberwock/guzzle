import { invoke } from "@tauri-apps/api/core";
import type {
  FunctionSignature,
  ToolchainInfo,
  CompileSettings,
  CrashFile,
  AiProvider,
} from "../store/session";

export interface FuzzerArgs {
  binary: string;
  corpus_dir: string;
  max_total_time: number;
  jobs: number;
}

export async function checkToolchain(): Promise<ToolchainInfo> {
  return invoke("check_toolchain");
}

export async function parseFunctionAtLine(
  filePath: string,
  lineNumber: number
): Promise<FunctionSignature | null> {
  return invoke("parse_function_at_line", { filePath, lineNumber });
}

export async function generateHarness(
  provider: AiProvider,
  signature: FunctionSignature,
  contextLines: string
): Promise<string> {
  return invoke("generate_harness", { provider, signature, contextLines });
}

export async function compileHarness(args: {
  harness: string;
  targetFiles: string[];
  settings: CompileSettings;
}): Promise<string> {
  return invoke("compile_harness", args);
}

export async function startFuzzer(args: FuzzerArgs): Promise<number> {
  return invoke("start_fuzzer", { args });
}

export async function stopFuzzer(pid: number): Promise<void> {
  return invoke("stop_fuzzer", { pid });
}

export async function readCrashFiles(corpusDir: string): Promise<CrashFile[]> {
  return invoke("read_crash_files", { corpusDir });
}

export async function saveApiKey(providerName: string, key: string): Promise<void> {
  return invoke("save_api_key", { providerName, key });
}

export async function loadApiKey(providerName: string): Promise<string | null> {
  return invoke("load_api_key", { providerName });
}

export async function revealInFinder(path: string): Promise<void> {
  return invoke("reveal_in_finder", { path });
}
