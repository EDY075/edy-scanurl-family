import { useEffect, useState } from "react";
import { checkHealth, type HealthState } from "../services/api";

export function useHealth() {
  const [state, setState] = useState<HealthState>("checking");
  const [attempt, setAttempt] = useState(0);
  const [offline, setOffline] = useState(!navigator.onLine);
  useEffect(() => {
    const update = () => {
      setOffline(!navigator.onLine);
      setAttempt((value) => value + 1);
    };
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let retry: ReturnType<typeof setTimeout> | undefined;
    setState(offline ? "offline" : "checking");
    if (!offline)
      void checkHealth(controller.signal).then((result) => {
        if (controller.signal.aborted) return;
        setState(result);
        // One retry per cycle, not indefinite polling or enrollment on launch.
        if (result !== "online")
          retry = setTimeout(() => {
            void checkHealth(controller.signal).then((next) => {
              if (!controller.signal.aborted) setState(next === 'degraded' ? 'unavailable' : next);
            });
          }, 10_000);
      });
    return () => {
      controller.abort();
      clearTimeout(retry);
    };
  }, [attempt, offline]);
  return {
    state,
    offline,
    retry: () => {
      if (state !== "checking") setAttempt((value) => value + 1);
    },
  };
}
