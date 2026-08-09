import { useEffect, useState } from "react";

/**
 * Types `text` character by character. Returns the revealed substring and a
 * `done` flag. Restarts whenever `text` changes identity.
 */
export function useTypewriter(text = "", speed = 22, startDelay = 350) {
  const [count, setCount] = useState(0);
  const [done, setDone] = useState(false);

  useEffect(() => {
    setCount(0);
    setDone(false);
    let interval;
    const start = setTimeout(() => {
      interval = setInterval(() => {
        setCount((c) => {
          if (c >= text.length) {
            clearInterval(interval);
            setDone(true);
            return c;
          }
          return c + 1;
        });
      }, speed);
    }, startDelay);
    return () => {
      clearTimeout(start);
      clearInterval(interval);
    };
  }, [text, speed, startDelay]);

  return { revealed: text.slice(0, count), count, done };
}

/**
 * Types an array of lines sequentially (line by line, char by char),
 * reporting each completed line via `onLine` and completion via `onComplete`.
 */
export function useTypewriterLines(lines = [], speed = 14) {
  const [completed, setCompleted] = useState([]);
  const [current, setCurrent] = useState("");
  const [lineIdx, setLineIdx] = useState(0);
  const [charIdx, setCharIdx] = useState(0);

  useEffect(() => {
    setCompleted([]);
    setCurrent("");
    setLineIdx(0);
    setCharIdx(0);
  }, [lines]);

  useEffect(() => {
    if (lineIdx >= lines.length) return;
    if (charIdx <= lines[lineIdx].length) {
      const t = setTimeout(() => {
        setCurrent(lines[lineIdx].slice(0, charIdx));
        setCharIdx((c) => c + 1);
      }, speed);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      setCompleted((prev) => [...prev, lines[lineIdx]]);
      setLineIdx((l) => l + 1);
      setCharIdx(0);
      setCurrent("");
    }, 200);
    return () => clearTimeout(t);
  }, [lines, lineIdx, charIdx, speed]);

  return { completed, current, done: lineIdx >= lines.length };
}
