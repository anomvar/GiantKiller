import { useEffect, useState } from "react";

/**
 * Applies an intermittent holographic flicker to a DOM element every
 * `interval` ms. Pass the element ref returned from useRef().
 */
export function useHologramGlow(interval = 3200) {
  const [ref, setRef] = useState(null);
  useEffect(() => {
    if (!ref) return;
    const timer = setInterval(() => {
      ref.classList.remove("holo-flicker");
      void ref.offsetWidth;
      ref.classList.add("holo-flicker");
      setTimeout(() => ref.classList.remove("holo-flicker"), 180);
    }, interval);
    return () => clearInterval(timer);
  }, [ref, interval]);
  return setRef;
}

/**
 * Detects WebGL availability once. Used to swap to a 2D fallback on
 * machines (or remote desktops) without GPU acceleration.
 */
export function useWebGLSupport() {
  const [supported, setSupported] = useState(null);
  useEffect(() => {
    try {
      const canvas = document.createElement("canvas");
      const gl =
        canvas.getContext("webgl2") ||
        canvas.getContext("webgl") ||
        canvas.getContext("experimental-webgl");
      setSupported(Boolean(gl));
    } catch {
      setSupported(false);
    }
  }, []);
  return supported;
}
