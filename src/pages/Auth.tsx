import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Mail, Lock, User, Eye, EyeOff, AlertCircle, Github, KeyRound } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

const SECURITY_NOTES = [
  "Encrypted in transit (TLS 1.3)",
  "Optional two-factor authentication",
  "Session activity logging",
];

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{ username?: string; email?: string; password?: string }>({});

  const { signIn, signUp } = useAuth();
  const navigate = useNavigate();

  const isValidEmail = (val: string) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(val.trim());

  function validate(): boolean {
    const errs: { username?: string; email?: string; password?: string } = {};
    if (!isLogin && !username.trim()) errs.username = "Username is required.";
    else if (!isLogin && username.trim().length < 3) errs.username = "Username must be at least 3 characters.";
    if (!email.trim()) errs.email = "Email is required.";
    else if (!isValidEmail(email)) errs.email = "Enter a valid email address (e.g. user@example.com).";
    if (!password) errs.password = "Password is required.";
    else if (!isLogin && password.length < 6) errs.password = "Password must be at least 6 characters.";
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  }

  const handleSubmit = async () => {
    setError("");
    if (!validate()) return;
    setLoading(true);
    const result = isLogin ? await signIn(email, password) : await signUp(username, email, password);
    setLoading(false);
    if (result.error) setError(result.error);
    else navigate("/dashboard");
  };

  const switchMode = (login: boolean) => {
    setIsLogin(login);
    setError("");
    setUsername("");
    setEmail("");
    setPassword("");
    setFieldErrors({});
  };

  return (
    <div className="min-h-screen bg-background flex flex-col md:flex-row">
      {/* Left brand panel */}
      <div className="relative hidden md:flex flex-col justify-between w-[42%] max-w-[605px] bg-[#12161c] border-r border-border px-12 py-12 overflow-hidden">
        <div
          className="absolute inset-0 opacity-40 pointer-events-none"
          style={{
            backgroundImage:
              "linear-gradient(180deg, rgb(22,27,34) 3%, rgba(22,27,34,0) 3%), linear-gradient(90deg, rgb(22,27,34) 3%, rgba(22,27,34,0) 3%)",
            backgroundSize: "24px 24px",
          }}
        />
        <Link to="/" className="relative flex items-center gap-[5px]">
          <Shield className="h-7 w-7 text-primary" />
          <span className="font-sans text-xl font-bold tracking-[-0.5px] text-foreground">BlackShield</span>
        </Link>

        <div className="relative flex flex-col gap-4 max-w-sm">
          <h1 className="font-sans font-semibold text-2xl leading-[33px] text-foreground">
            One workspace for security analysis and controlled simulation.
          </h1>
          <p className="text-sm text-muted-foreground leading-[22.75px]">
            Sign in to access your scans, findings and training environment.
          </p>

          <div className="bg-black/20 border border-border rounded-lg p-[17px] flex flex-col gap-3 mt-2">
            <div className="flex items-center gap-2">
              <Lock className="h-3 w-3 text-muted-foreground" />
              <span className="font-sans font-semibold text-xs text-muted-foreground tracking-[0.6px] uppercase">
                Session security
              </span>
            </div>
            <ul className="flex flex-col gap-2">
              {SECURITY_NOTES.map((note) => (
                <li key={note} className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="text-primary">✓</span>
                  {note}
                </li>
              ))}
            </ul>
          </div>
        </div>

        <p className="relative text-xs text-muted-foreground/60">© 2024 BlackShield Inc.</p>
      </div>

      {/* Right form panel */}
      <div className="flex-1 flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-[448px] flex flex-col gap-8">
          {/* Tabs */}
          <div className="bg-[#12161c] border border-border rounded-md p-[5px] flex gap-1 self-start">
            <button
              onClick={() => switchMode(true)}
              className={`px-[17px] py-[7px] rounded text-sm font-medium transition-colors ${
                isLogin ? "bg-[#161b22] border border-border text-foreground" : "text-muted-foreground"
              }`}
            >
              Log in
            </button>
            <button
              onClick={() => switchMode(false)}
              className={`px-4 py-[7px] rounded text-sm font-medium transition-colors ${
                !isLogin ? "bg-[#161b22] border border-border text-foreground" : "text-muted-foreground"
              }`}
            >
              Create account
            </button>
          </div>

          <div className="flex flex-col gap-1.5">
            <h2 className="font-sans font-semibold text-2xl text-foreground">
              {isLogin ? "Welcome back" : "Create your workspace"}
            </h2>
            <p className="text-sm text-muted-foreground">
              {isLogin ? "Log in to continue to your workspace." : "Set up your BlackShield account."}
            </p>
          </div>

          <div className="flex flex-col gap-5">
            {!isLogin && (
              <div className="flex flex-col gap-2">
                <label className="text-xs font-medium text-muted-foreground">Username</label>
                <div className="relative">
                  <User className="absolute left-[15px] top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60" />
                  <input
                    value={username}
                    onChange={(e) => { setUsername(e.target.value); setFieldErrors((p) => ({ ...p, username: undefined })); }}
                    placeholder="yourhandle"
                    className={`w-full bg-[#161b22] border rounded-md pl-10 pr-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary ${
                      fieldErrors.username ? "border-destructive" : "border-border"
                    }`}
                  />
                </div>
                {fieldErrors.username && (
                  <p className="flex items-center gap-1.5 text-xs text-destructive"><AlertCircle className="h-3 w-3" />{fieldErrors.username}</p>
                )}
              </div>
            )}

            <div className="flex flex-col gap-2">
              <label className="text-xs font-medium text-muted-foreground">Work email</label>
              <div className="relative">
                <Mail className="absolute left-[15px] top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setFieldErrors((p) => ({ ...p, email: undefined })); }}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                  placeholder="you@company.com"
                  className={`w-full bg-[#161b22] border rounded-md pl-10 pr-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary ${
                    fieldErrors.email ? "border-destructive" : "border-border"
                  }`}
                />
              </div>
              {fieldErrors.email && (
                <p className="flex items-center gap-1.5 text-xs text-destructive"><AlertCircle className="h-3 w-3" />{fieldErrors.email}</p>
              )}
            </div>

            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-muted-foreground">Password</label>
                {isLogin && (
                  <span title="Not available yet" className="text-xs text-primary/60 cursor-not-allowed">
                    Forgot password?
                  </span>
                )}
              </div>
              <div className="relative">
                <Lock className="absolute left-[15px] top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/60" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setFieldErrors((p) => ({ ...p, password: undefined })); }}
                  onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                  placeholder="••••••••••••"
                  className={`w-full bg-[#161b22] border rounded-md pl-10 pr-10 py-3 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary ${
                    fieldErrors.password ? "border-destructive" : "border-border"
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {fieldErrors.password && (
                <p className="flex items-center gap-1.5 text-xs text-destructive"><AlertCircle className="h-3 w-3" />{fieldErrors.password}</p>
              )}
            </div>

            {isLogin && (
              <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
                <input
                  type="checkbox"
                  checked={keepSignedIn}
                  onChange={(e) => setKeepSignedIn(e.target.checked)}
                  className="h-4 w-4 rounded border-border accent-primary"
                />
                Keep me signed in on this device
              </label>
            )}

            {error && (
              <div className="flex items-center gap-2 text-destructive text-sm bg-destructive/10 border border-destructive/30 rounded px-3 py-2">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <button
              onClick={handleSubmit}
              disabled={loading}
              className="w-full bg-primary hover:bg-primary/90 disabled:opacity-60 text-primary-foreground font-medium text-sm rounded-md py-2.5 transition-colors"
            >
              {loading ? "Processing..." : isLogin ? "Log in" : "Create account"}
            </button>

            <div className="flex items-center gap-3 pt-1">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-muted-foreground/60">or continue with</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            <div className="flex gap-3">
              <button
                type="button"
                title="Not available yet"
                disabled
                className="flex-1 flex items-center justify-center gap-2 border border-border rounded-md py-2.5 text-sm font-medium text-foreground/60 cursor-not-allowed"
              >
                <Github className="h-3.5 w-3.5" /> GitHub
              </button>
              <button
                type="button"
                title="Not available yet"
                disabled
                className="flex-1 flex items-center justify-center gap-2 border border-border rounded-md py-2.5 text-sm font-medium text-foreground/60 cursor-not-allowed"
              >
                <KeyRound className="h-3.5 w-3.5" /> SSO
              </button>
            </div>

            <p className="text-center text-sm text-muted-foreground pt-1">
              {isLogin ? "Don't have an account? " : "Already have an account? "}
              <button onClick={() => switchMode(!isLogin)} className="text-primary hover:underline">
                {isLogin ? "Create one" : "Log in"}
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Auth;
