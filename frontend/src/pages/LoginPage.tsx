import { useState, useEffect, type FormEvent } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { loginUser, getStoredToken } from "../lib/api";

/* ------------------------------------------------------------------ */
/*  Inline SVG Icons (Zero Unicode Emojis)                             */
/* ------------------------------------------------------------------ */

const InvertedTriangleLogo = () => (
  <svg className="w-5 h-5 text-white fill-current" viewBox="0 0 76 65" fill="none">
    <path d="M37.5274 65L0 0H75.0548L37.5274 65Z" fill="currentColor" />
  </svg>
);

const EyeIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

const ArrowIcon = () => (
  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="5" y1="12" x2="19" y2="12" />
    <polyline points="12 5 19 12 12 19" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-3.5 h-3.5 text-[#71717a]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const AlertTriangleIcon = () => (
  <svg className="w-4 h-4 text-red-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

/* ------------------------------------------------------------------ */
/*  LoginPage Component (Pure Sign In)                                */
/* ------------------------------------------------------------------ */

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberDevice, setRememberDevice] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (getStoredToken()) {
      const destination = (location.state as any)?.from?.pathname || "/dashboard";
      navigate(destination, { replace: true });
    }
  }, [navigate, location]);

  const handleFormSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const cleanIdentifier = usernameOrEmail.trim();
    if (!cleanIdentifier || !password) {
      setErrorMessage("Please enter both username/email and password.");
      return;
    }

    setSubmitting(true);
    try {
      await loginUser({
        username_or_email: cleanIdentifier,
        password,
      });

      // Redirect to the originally intended destination or fall back to /dashboard
      const destination = (location.state as any)?.from?.pathname || "/dashboard";
      navigate(destination, { replace: true });
    } catch (err: any) {
      setErrorMessage(err.message || "Invalid credentials. Please verify your username and password.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="w-full max-w-[420px] mx-auto z-10 flex flex-col my-auto py-12 sm:py-16 px-4">
      {/* ── Top Geometric Minimal Brand Mark ── */}
      <div className="flex flex-col items-center mb-6">
        <div className="w-10 h-10 rounded-lg bg-[#111113] border border-[#1e1e22] flex items-center justify-center shadow-md mb-3">
          <InvertedTriangleLogo />
        </div>
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#111113] border border-[#1e1e22]">
          <span className="w-1.5 h-1.5 rounded-full bg-white" />
          <span className="font-mono text-[11px] text-[#ededed] font-medium">
            Geist Security
          </span>
          <span className="text-[#3f3f46]">/</span>
          <span className="text-[11px] font-mono text-[#71717a]">
            Authentication Gateway
          </span>
        </div>
      </div>

      {/* ── Core Auth Card ── */}
      <div className="bg-[#0a0a0a] border border-[#1e1e22] rounded-xl shadow-2xl p-6 sm:p-7 flex flex-col relative overflow-hidden">
        {/* ── Heading Block ── */}
        <div className="flex flex-col mb-5">
          <h1 className="text-lg font-semibold text-white tracking-tight">
            Sign In
          </h1>
          <p className="text-xs text-[#71717a] mt-1 font-sans">
            Enter your operator credentials to access the security workspace.
          </p>
        </div>

        {/* ── Error Banner ── */}
        {errorMessage && (
          <div className="mb-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center gap-2.5 text-xs text-red-400 font-mono leading-relaxed">
            <AlertTriangleIcon />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* ── Form Fields ── */}
        <form className="flex flex-col gap-4" onSubmit={handleFormSubmit}>
          {/* Username or Email Field */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono text-[#a1a1aa] flex items-center justify-between" htmlFor="login-identifier">
              <span>Username or Email</span>
              <span className="text-[10px] text-[#52525b]">Required</span>
            </label>
            <input
              id="login-identifier"
              type="text"
              required
              autoFocus
              value={usernameOrEmail}
              onChange={(e) => setUsernameOrEmail(e.target.value)}
              placeholder="operator or user@corp.io"
              className="w-full h-9 px-3 bg-[#111113] rounded-lg font-mono text-xs text-white placeholder:text-[#52525b] border border-[#1e1e22] focus:border-[#71717a] focus:bg-[#111113] focus:outline-none transition-colors"
            />
          </div>

          {/* Password Field */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-mono text-[#a1a1aa]" htmlFor="login-password">
                Password
              </label>
            </div>
            <div className="relative flex items-center">
              <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full h-9 px-3 pr-10 bg-[#111113] rounded-lg font-mono text-xs text-white placeholder:text-[#52525b] border border-[#1e1e22] focus:border-[#71717a] focus:bg-[#111113] focus:outline-none transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute right-2.5 p-1 text-[#52525b] hover:text-[#ededed] transition-colors flex items-center justify-center focus:outline-none"
                title="Toggle visibility"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
          </div>

          {/* Remember Session Checkbox + Badge */}
          <div className="flex items-center justify-between pt-1">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={rememberDevice}
                onChange={(e) => setRememberDevice(e.target.checked)}
                className="w-3.5 h-3.5 rounded bg-[#111113] border border-[#27272a] accent-white cursor-pointer transition-colors"
              />
              <span className="text-xs text-[#71717a]">
                Remember session
              </span>
            </label>
            <span className="text-[10px] font-mono text-[#71717a] bg-[#111113] px-1.5 py-0.5 rounded border border-[#1e1e22]">
              PBKDF2-SHA256
            </span>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={submitting}
            className="w-full mt-2 h-9 rounded-lg bg-white text-black font-semibold text-xs font-mono hover:bg-[#e5e2e1] active:scale-[0.99] transition-all flex items-center justify-center gap-1.5 shadow-sm cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <span>
              {submitting ? "Verifying credentials..." : "Sign In"}
            </span>
            {!submitting && <ArrowIcon />}
          </button>
        </form>

        {/* ── Bottom Link to Register Page ── */}
        <div className="mt-5 pt-4 bg-[#111113]/50 -mx-6 sm:-mx-7 -mb-6 sm:-mb-7 px-6 sm:px-7 py-3 flex items-center justify-center gap-1.5 border-t border-[#1e1e22] text-xs font-mono text-[#71717a]">
          <span>Need a new operator account?</span>
          <Link
            to="/register"
            className="text-white font-medium hover:underline focus:outline-none transition-colors"
          >
            Register
          </Link>
        </div>
      </div>

      {/* ── Security Badges Below Card ── */}
      <div className="mt-6 flex flex-col items-center gap-2 text-center">
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#111113] border border-[#1e1e22]">
          <ShieldIcon />
          <span className="text-xs font-mono text-[#71717a]">
            Zero-Trust Architecture · Salted PBKDF2
          </span>
        </div>
        <div className="flex items-center gap-3 text-[#52525b] text-[11px] font-mono">
          <span>Enterprise Access Control</span>
          <span>·</span>
          <span>Zero Third-Party Tracking</span>
        </div>
      </div>
    </div>
  );
}
