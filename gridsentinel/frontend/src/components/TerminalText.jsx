import { useTypewriterLines } from "../hooks/useTypewriter";

/**
 * A terminal-style line typer. Renders each line with the `> ` prompt and a
 * blinking cursor on the line currently being typed.
 */
export default function TerminalText({
  lines = [],
  speed = 14,
  prefix = ">",
  className = "",
  accent = "text-cyan-300",
}) {
  const { completed, current, done } = useTypewriterLines(lines, speed);

  return (
    <div className={`font-mono text-xs leading-6 ${className}`}>
      {completed.map((line, i) => (
        <div key={`${i}-${line}`} className="text-slate-300">
          <span className={`${accent} mr-1`}>{prefix}</span>
          {line}
        </div>
      ))}
      {(completed.length < lines.length || !done) && (
        <div>
          <span className={`${accent} mr-1`}>{prefix}</span>
          {current}
          <span className="cursor-blink ml-0.5" />
        </div>
      )}
    </div>
  );
}
