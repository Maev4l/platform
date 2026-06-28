import { useSyncExternalStore } from 'react';

// Thin fetch wrapper for same-origin /api/* calls.
// No Authorization header — the binary gates access via SSO at startup.

// In-flight request tracking so the UI can show a global loading indicator.
let inFlight = 0;
const listeners = new Set();
const notify = () => listeners.forEach((l) => l());

export const api = async (path, params = {}) => {
  const qs = new URLSearchParams(params).toString();
  inFlight += 1;
  notify();
  try {
    const res = await fetch(`${path}${qs ? `?${qs}` : ''}`);
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return await res.json();
  } finally {
    inFlight -= 1;
    notify();
  }
};

// React hook: true while any api() request is in flight.
export const useApiLoading = () =>
  useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => inFlight > 0,
  );
