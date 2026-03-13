import { useCallback, useRef, useState } from "react";
import MonacoEditor from "@monaco-editor/react";
import { useSession } from "../../store/session";
import { parseFunctionAtLine } from "../../lib/tauri";
import FunctionBanner from "./FunctionBanner";

export default function SourceViewer() {
  const { fileContent, filePath, functionSignature, setSelectedLine, setFunctionSignature, openWizard } =
    useSession();
  const [detecting, setDetecting] = useState(false);
  const detectTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleLineClick = useCallback(
    (lineNumber: number) => {
      if (!filePath) return;
      setSelectedLine(lineNumber);

      if (detectTimeout.current) clearTimeout(detectTimeout.current);

      detectTimeout.current = setTimeout(async () => {
        setDetecting(true);
        setFunctionSignature(null);
        try {
          const sig = await parseFunctionAtLine(filePath, lineNumber);
          setFunctionSignature(sig);
        } catch (e) {
          console.error("parse error", e);
          setFunctionSignature(null);
        } finally {
          setDetecting(false);
        }
      }, 200);
    },
    [filePath, setSelectedLine, setFunctionSignature]
  );

  const handleEditorMount = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (editor: any) => {
      editor.onDidChangeCursorPosition((e: { position: { lineNumber: number } }) => {
        handleLineClick(e.position.lineNumber);
      });
    },
    [handleLineClick]
  );

  const language = filePath?.endsWith(".c") ? "c" : "cpp";

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="flex-1 min-h-0">
        <MonacoEditor
          height="100%"
          language={language}
          value={fileContent ?? "// Open a C/C++ file to get started"}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: true },
            fontSize: 13,
            lineNumbers: "on",
            scrollBeyondLastLine: false,
            wordWrap: "off",
            renderLineHighlight: "all",
          }}
          onMount={handleEditorMount}
        />
      </div>
      <FunctionBanner
        signature={functionSignature}
        loading={detecting}
        onFuzz={() => {
          if (functionSignature) openWizard();
        }}
      />
    </div>
  );
}
