// Thin fetch wrapper for same-origin /api/* calls.
// No Authorization header — the binary gates access via SSO at startup.
export const api = async (path, params = {}) => {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${path}${qs ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
};
