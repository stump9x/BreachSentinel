import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  api,
  clearAuth,
  hasAuth,
  loadStoredAuth,
  loginWithPassword,
  logoutRemote,
} from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authed, setAuthed] = useState(() => hasAuth());
  const [username, setUsername] = useState(() => (hasAuth() ? "analyst" : ""));
  const [isStaff, setIsStaff] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!hasAuth()) return undefined;
    let cancelled = false;
    (async () => {
      try {
        const me = await api.get("/api/v1/auth/me/");
        if (cancelled) return;
        setAuthed(true);
        setUsername(me.username || "analyst");
        setIsStaff(Boolean(me.is_staff));
      } catch {
        if (cancelled) return;
        clearAuth();
        setAuthed(false);
        setUsername("");
        setIsStaff(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (user, password) => {
    setError("");
    try {
      const data = await loginWithPassword(user, password);
      setAuthed(true);
      setUsername(data.username || user);
      setIsStaff(Boolean(data.is_staff));
    } catch (err) {
      clearAuth();
      setAuthed(false);
      setUsername("");
      setIsStaff(false);
      const msg =
        err instanceof ApiError && err.status === 401
          ? "Invalid username or password"
          : err.message || "Login failed";
      setError(msg);
      throw err;
    }
  }, []);

  const logout = useCallback(async () => {
    await logoutRemote();
    setAuthed(false);
    setUsername("");
    setIsStaff(false);
    setError("");
  }, []);

  const value = useMemo(
    () => ({
      authed: authed && Boolean(loadStoredAuth()),
      username,
      isStaff,
      error,
      login,
      logout,
      clearError: () => setError(""),
    }),
    [authed, username, isStaff, error, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
