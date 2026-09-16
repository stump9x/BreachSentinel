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
  const [isSuperuser, setIsSuperuser] = useState(false);
  const [profileLoading, setProfileLoading] = useState(() => hasAuth());
  const [error, setError] = useState("");

  useEffect(() => {
    if (!hasAuth()) {
      setProfileLoading(false);
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const me = await api.get("/api/v1/auth/me/");
        if (cancelled) return;
        setAuthed(true);
        setUsername(me.username || "analyst");
        setIsStaff(Boolean(me.is_staff));
        setIsSuperuser(Boolean(me.is_superuser));
      } catch {
        if (cancelled) return;
        clearAuth();
        setAuthed(false);
        setUsername("");
        setIsStaff(false);
        setIsSuperuser(false);
      } finally {
        if (!cancelled) setProfileLoading(false);
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
      setIsSuperuser(Boolean(data.is_superuser));
      setProfileLoading(false);
    } catch (err) {
      clearAuth();
      setAuthed(false);
      setUsername("");
      setIsStaff(false);
      setIsSuperuser(false);
      setProfileLoading(false);
      const msg =
        err instanceof ApiError && err.payload?.code === "account_pending"
          ? "Tài khoản đang chờ quản trị viên phê duyệt."
          : err instanceof ApiError && err.payload?.code === "account_rejected"
            ? "Yêu cầu truy cập đã bị từ chối."
            : err instanceof ApiError && err.payload?.code === "account_revoked"
              ? "Quyền truy cập của tài khoản đã bị thu hồi."
              : err instanceof ApiError && err.status === 401
                ? "Tên đăng nhập hoặc mật khẩu không đúng."
                : err.message || "Không thể đăng nhập";
      setError(msg);
      throw err;
    }
  }, []);

  const logout = useCallback(async () => {
    await logoutRemote();
    setAuthed(false);
    setUsername("");
    setIsStaff(false);
    setIsSuperuser(false);
    setProfileLoading(false);
    setError("");
  }, []);

  const value = useMemo(
    () => ({
      authed: authed && Boolean(loadStoredAuth()),
      username,
      isStaff,
      isSuperuser,
      profileLoading,
      error,
      login,
      logout,
      clearError: () => setError(""),
    }),
    [authed, username, isStaff, isSuperuser, profileLoading, error, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
