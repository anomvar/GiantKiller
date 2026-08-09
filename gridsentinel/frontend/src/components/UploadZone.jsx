import { useCallback, useRef, useState } from "react";
import { uploadFile, triggerScan } from "../api";

const ACCEPTED = [".exe", ".dll", ".msi", ".elf", ".zip", ".bin", ".scr", ".cpl"];

export default function UploadZone({ onScanCreated }) {
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  const validate = (file) => {
    const name = file.name.toLowerCase();
    const ok = ACCEPTED.some((ext) => name.endsWith(ext));
    if (!ok) throw new Error(`Unsupported format. Allowed: ${ACCEPTED.join(", ")}`);
    if (file.size > 50 * 1024 * 1024) throw new Error("File exceeds 50MB limit");
  };

  const handleFile = useCallback(
    async (file) => {
      setError(null);
      setBusy(true);
      setProgress(0);
      try {
        validate(file);
        const up = await uploadFile(file, setProgress);
        setProgress(100);
        const trig = await triggerScan(up.scan_id);
        onScanCreated(up.scan_id, up.filename, trig);
      } catch (e) {
        setError(e.message || "Upload failed");
      } finally {
        setBusy(false);
      }
    },
    [onScanCreated]
  );

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        onClick={() => !busy && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`relative rounded-2xl border-2 border-dashed p-10 text-center transition-all cursor-pointer bg-slate-900/60 backdrop-blur ${
          dragging ? "border-cyan-400 glow-cyan" : "border-slate-600 hover:border-cyan-400/60"
        }`}
      >
        <div className="text-5xl mb-4">🛰️</div>
        <h2 className="text-xl font-semibold text-cyan-300 mb-1">Submit Software for Forensic Autopsy</h2>
        <p className="text-slate-400 text-sm mb-6">
          Drag & drop a PE/ELF binary here, or click to browse
        </p>

        {busy && (
          <div className="w-full bg-slate-800 rounded-full h-2 mb-4 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        )}
        {busy && (
          <p className="text-xs text-cyan-400 font-mono mb-4">
            {progress < 100 ? `Uploading… ${progress}%` : "Queuing scan pipeline…"}
          </p>
        )}

        {!busy && (
          <div className="flex flex-wrap gap-2 justify-center text-[11px] font-mono text-slate-500">
            {ACCEPTED.slice(0, 5).map((e) => (
              <span key={e} className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                {e}
              </span>
            ))}
          </div>
        )}

        {error && (
          <p className="mt-4 text-red-400 text-sm bg-red-500/10 border border-red-500/40 rounded-lg p-2">
            {error}
          </p>
        )}

        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
      </div>

      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-slate-400">
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3">
          <div className="text-cyan-400 font-semibold mb-1">① Software Autopsy</div>
          PE structure, entropy, imports, certs, strings & YARA — dissected like a CT scan.
        </div>
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3">
          <div className="text-emerald-400 font-semibold mb-1">② Deceptive Sandbox</div>
          Anti-anti-VM hooks that trick malware into activating and revealing its C2.
        </div>
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3">
          <div className="text-amber-400 font-semibold mb-1">③ Grid Impact Twin</div>
          Maps detected behavior onto a 220kV substation topology in real time.
        </div>
      </div>
    </div>
  );
}
