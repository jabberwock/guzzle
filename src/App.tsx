import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { useSession } from "./store/session";
import SourceViewer from "./components/SourceViewer";
import Wizard from "./components/Wizard";

function HomePage({ onOpen }: { onOpen: () => void }) {
  const { recentFiles, setFilePath, addRecentFile } = useSession();

  const openRecent = async (path: string) => {
    try {
      const content = await readTextFile(path);
      setFilePath(path, content);
      addRecentFile(path);
    } catch (e) {
      console.error("Failed to open recent file", e);
    }
  };

  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-8 p-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-[#e6edf3] mb-2">
          ⚡ Guzzle
        </h1>
        <p className="text-[#8b949e] text-lg">
          libFuzzer made easy — open a C/C++ file and fuzz any function in minutes.
        </p>
      </div>

      <button
        onClick={onOpen}
        className="px-8 py-4 bg-[#238636] hover:bg-[#2ea043] text-white font-semibold rounded-xl text-lg transition-colors shadow-lg"
      >
        Open C/C++ File…
      </button>

      {recentFiles.length > 0 && (
        <div className="w-full max-w-md">
          <p className="text-xs text-[#8b949e] uppercase tracking-wider mb-3">Recent Files</p>
          <div className="flex flex-col gap-1">
            {recentFiles.map((f) => (
              <button
                key={f}
                onClick={() => openRecent(f)}
                className="text-left px-4 py-2.5 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] rounded-lg text-sm text-[#e6edf3] font-mono truncate transition-colors"
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Header({ filePath, onOpen }: { filePath: string | null; onOpen: () => void }) {
  return (
    <div className="flex items-center justify-between px-4 py-2 bg-[#161b22] border-b border-[#30363d]">
      <div className="flex items-center gap-3">
        <span className="font-bold text-[#e6edf3]">⚡ Guzzle</span>
        {filePath && (
          <>
            <span className="text-[#30363d]">/</span>
            <span className="text-sm text-[#8b949e] font-mono truncate max-w-xs">
              {filePath.split("/").pop()}
            </span>
          </>
        )}
      </div>
      <button
        onClick={onOpen}
        className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] text-sm text-[#e6edf3] rounded-md transition-colors"
      >
        Open file…
      </button>
    </div>
  );
}

export default function App() {
  const { filePath, setFilePath, addRecentFile } = useSession();

  const handleOpen = async () => {
    try {
      const selected = await open({
        filters: [{ name: "C/C++ Files", extensions: ["c", "cpp", "cc", "cxx", "h", "hpp"] }],
        multiple: false,
      });
      if (typeof selected === "string") {
        const content = await readTextFile(selected);
        setFilePath(selected, content);
        addRecentFile(selected);
      }
    } catch (e) {
      console.error("File open error", e);
    }
  };

  return (
    <div className="flex flex-col h-screen">
      {filePath && <Header filePath={filePath} onOpen={handleOpen} />}
      {filePath ? <SourceViewer /> : <HomePage onOpen={handleOpen} />}
      <Wizard />
    </div>
  );
}
