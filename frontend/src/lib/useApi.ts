"use client";

import { useEffect, useState } from "react";
import { ApiError } from "./api";

export type ApiState<T> = {
  data: T | null;
  error: string | null;
  loading: boolean;
};

/**
 * Runs a fetcher on mount (and whenever `deps` change), tracking
 * loading / error / data. Aborts the in-flight request on unmount or
 * dependency change so stale responses never clobber fresh state.
 */
export function useApi<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: unknown[]
): ApiState<T> {
  const [state, setState] = useState<ApiState<T>>({
    data: null,
    error: null,
    loading: true,
  });

  useEffect(() => {
    const ctrl = new AbortController();
    setState({ data: null, error: null, loading: true });

    fetcher(ctrl.signal)
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        const message =
          err instanceof ApiError
            ? err.message
            : "Something went wrong loading this.";
        setState({ data: null, error: message, loading: false });
      });

    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
