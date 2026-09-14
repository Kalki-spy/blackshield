import { createContext, useContext, useState, useEffect, ReactNode } from "react";

const AUTH_URL =
  import.meta.env.VITE_AUTH_URL || "/api";

const TOKEN_KEY = "bs_token";

interface User {
  id: number;
  username: string;
  email: string;
  created_at?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  signUp: (username: string, email: string, password: string) => Promise<{ error?: string }>;
  signIn: (email: string, password: string) => Promise<{ error?: string }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: true,
  signUp: async () => ({}),
  signIn: async () => ({}),
  signOut: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Restore session on mount
  useEffect(() => {
    const saved = localStorage.getItem(TOKEN_KEY);
    if (!saved) { setLoading(false); return; }
    fetch(`${AUTH_URL}/auth/me`, { headers: { Authorization: `Bearer ${saved}` } })
      .then((r) => r.json())
      .then((data) => {
        if (data.user) { setUser(data.user); setToken(saved); }
        else localStorage.removeItem(TOKEN_KEY);
      })
      .catch(() => localStorage.removeItem(TOKEN_KEY))
      .finally(() => setLoading(false));
  }, []);

  const signUp = async (username: string, email: string, password: string) => {
    try {
      const res = await fetch(`${AUTH_URL}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });
      const data = await res.json();
      if (!res.ok) return { error: data.error || "Signup failed" };
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token); setUser(data.user);
      return {};
    } catch { return { error: "Cannot connect to auth server. Is it running?" }; }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const res = await fetch(`${AUTH_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) return { error: data.error || "Login failed" };
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token); setUser(data.user);
      return {};
    } catch { return { error: "Cannot connect to auth server. Is it running?" }; }
  };

  const signOut = async () => {
    if (token) {
      await fetch(`${AUTH_URL}/auth/logout`, {
        method: "POST", headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
    localStorage.removeItem(TOKEN_KEY);
    setToken(null); setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, signUp, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}
