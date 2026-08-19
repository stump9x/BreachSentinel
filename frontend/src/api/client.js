/**
 * Browser API client for BreachSentinel DRF backend.
 * Auth: short-lived DRF Token via /api/v1/auth/login/ (sessionStorage).
 * Never stores passwords. Never logs secrets.
 *
 * credentials: "omit" — do not attach Django session cookies to API calls.
 */

const TOKEN_KEY = "bs_api_token";

export function getApiBase() {
  const base = import.meta.env.VITE_API_BASE_URL;
  return typeof base === "string" ? base.replace(/\/$/, "") : "";
}

export function loadStoredAuth() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function storeAuth(token) {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearAuth() {
  sessionStorage.removeItem(TOKEN_KEY);
}

export function hasAuth() {
  return Boolean(loadStoredAuth());
}

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

async function parseBody(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text.slice(0, 300) };
  }
}

function parseTextBody(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text.slice(0, 300) };
  }
}

function responseErrorMessage(payload, status) {
  const message =
    (payload && (payload.detail || payload.message || payload.error)) ||
    `HTTP ${status || 0}`;
  return typeof message === "string" ? message : JSON.stringify(message);
}

/**
 * Upload multipart data with browser-native byte progress.
 * XHR is intentional here: fetch does not expose request upload progress.
 */
export function uploadWithProgress(path, formData, options = {}) {
  const {
    auth = true,
    onProgress,
    signal,
    timeoutMs = 30 * 60 * 1000,
  } = options;

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    let settled = false;

    const cleanup = () => {
      signal?.removeEventListener("abort", abortRequest);
    };
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      callback(value);
    };
    const abortRequest = () => xhr.abort();

    if (signal?.aborted) {
      finish(reject, new DOMException("Upload aborted", "AbortError"));
      return;
    }

    xhr.open("POST", `${getApiBase()}${path}`);
    xhr.timeout = timeoutMs;
    xhr.setRequestHeader("Accept", "application/json");

    if (auth) {
      const token = loadStoredAuth();
      if (token) xhr.setRequestHeader("Authorization", `Token ${token}`);
    }

    xhr.upload.addEventListener("progress", (event) => {
      onProgress?.({
        loaded: event.loaded,
        total: event.lengthComputable ? event.total : 0,
        percent: event.lengthComputable && event.total
          ? Math.round((event.loaded / event.total) * 100)
          : null,
      });
    });
    xhr.addEventListener("load", () => {
      const payload = parseTextBody(xhr.responseText);
      if (xhr.status >= 200 && xhr.status < 300) {
        finish(resolve, payload);
        return;
      }
      finish(
        reject,
        new ApiError(responseErrorMessage(payload, xhr.status), xhr.status, payload)
      );
    });
    xhr.addEventListener("error", () => {
      finish(reject, new ApiError("Network error while uploading", 0, null));
    });
    xhr.addEventListener("timeout", () => {
      finish(reject, new ApiError("Upload timed out", 0, null));
    });
    xhr.addEventListener("abort", () => {
      finish(reject, new DOMException("Upload aborted", "AbortError"));
    });
    signal?.addEventListener("abort", abortRequest, { once: true });
    xhr.send(formData);
  });
}

export async function apiRequest(path, options = {}) {
  const {
    method = "GET",
    body,
    auth = true,
    headers: extraHeaders = {},
    signal,
    retries = method === "GET" ? 2 : 0,
    formData = false,
  } = options;

  const headers = {
    Accept: "application/json",
    ...extraHeaders,
  };

  if (body !== undefined && !formData) {
    headers["Content-Type"] = "application/json";
  }

  if (auth) {
    const token = loadStoredAuth();
    if (token) {
      headers.Authorization = `Token ${token}`;
    }
  }

  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const response = await fetch(`${getApiBase()}${path}`, {
      method,
      headers,
      body:
        body === undefined
          ? undefined
          : formData
            ? body
            : JSON.stringify(body),
      signal,
      credentials: "omit",
    });

    const payload = await parseBody(response);
    if (response.ok) {
      return payload;
    }

    const message =
      (payload && (payload.detail || payload.message || payload.error)) ||
      `HTTP ${response.status}`;
    lastError = new ApiError(
      typeof message === "string" ? message : JSON.stringify(message),
      response.status,
      payload
    );

    // Brief retry on gateway blips while backend is still booting.
    if (
      attempt < retries &&
      (response.status === 502 || response.status === 503 || response.status === 504)
    ) {
      await new Promise((r) => setTimeout(r, 400 * (attempt + 1)));
      continue;
    }
    throw lastError;
  }
  throw lastError;
}

export const api = {
  get: (path, opts) => apiRequest(path, { ...opts, method: "GET" }),
  post: (path, body, opts) => apiRequest(path, { ...opts, method: "POST", body }),
  patch: (path, body, opts) => apiRequest(path, { ...opts, method: "PATCH", body }),
  delete: (path, opts) => apiRequest(path, { ...opts, method: "DELETE" }),
  upload: (path, formData, opts) =>
    apiRequest(path, { ...opts, method: "POST", body: formData, formData: true, retries: 0 }),
  uploadWithProgress,
};

export async function loginWithPassword(username, password) {
  clearAuth();
  const data = await apiRequest("/api/v1/auth/login/", {
    method: "POST",
    body: { username, password },
    auth: false,
  });
  if (!data?.token) {
    throw new ApiError("Login response missing token", 500, data);
  }
  storeAuth(data.token);
  return {
    username: data.username || username,
    is_staff: Boolean(data.is_staff),
    expires_in_hours: data.expires_in_hours,
  };
}

export async function logoutRemote() {
  try {
    if (hasAuth()) {
      await api.post("/api/v1/auth/logout/", {});
    }
  } catch {
    // best-effort
  } finally {
    clearAuth();
  }
}

export function buildQuery(params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    qs.set(key, String(value));
  });
  const s = qs.toString();
  return s ? `?${s}` : "";
}
