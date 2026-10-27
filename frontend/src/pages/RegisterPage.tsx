import { useState, useEffect, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { registerUser, getStoredToken } from "../lib/api";

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

const CheckIcon = () => (
  <svg className="w-3.5 h-3.5 text-black" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-3.5 h-3.5 text-[#71717a]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const LockOpenIcon = () => (
  <svg className="w-3.5 h-3.5 text-[#71717a]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 9.9-1" />
  </svg>
);

const BoltIcon = () => (
  <svg className="w-3.5 h-3.5 text-[#71717a]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
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
/*  RegisterPage Component                                             */
/* ------------------------------------------------------------------ */

export default function RegisterPage() {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [agreeTerms, setAgreeTerms] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (getStoredToken()) {
      navigate("/dashboard", { replace: true });
    }
  }, [navigate]);

  // Password rules validation
  const hasLength = password.length >= 8;
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  const hasEntropy = password.length >= 12 && hasNumber && hasSymbol;

  // Strength score: 0 to 4
  let score = 0;
  if (password.length > 0) score += 1;
  if (hasLength && (hasNumber || hasSymbol)) score += 1;
  if (hasLength && hasNumber && hasSymbol) score += 1;
  if (hasEntropy) score += 1;

  const strengthConfig = [
    {
      label: "Empty",
      labelColor: "text-[#52525b]",
      barColors: ["bg-[#1e1e22]", "bg-[#1e1e22]", "bg-[#1e1e22]", "bg-[#1e1e22]"],
    },
    {
      label: "Weak",
      labelColor: "text-red-400",
      barColors: ["bg-red-400", "bg-[#1e1e22]", "bg-[#1e1e22]", "bg-[#1e1e22]"],
    },
    {
      label: "Fair",
      labelColor: "text-amber-400",
      barColors: ["bg-amber-400", "bg-amber-400", "bg-[#1e1e22]", "bg-[#1e1e22]"],
    },
    {
      label: "Good",
      labelColor: "text-emerald-400",
      barColors: ["bg-emerald-400", "bg-emerald-400", "bg-emerald-400", "bg-[#1e1e22]"],
    },
    {
      label: "Secure",
      labelColor: "text-white font-medium",
      barColors: ["bg-white", "bg-white", "bg-white", "bg-white"],
    },
  ];

  const currentStrength = strengthConfig[score];

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!agreeTerms) {
      setErrorMessage("Please accept the Terms of Service to create an account.");
      return;
    }

    if (!username.trim() || !email.trim() || !password) {
      setErrorMessage("Username, email, and password are required.");
      return;
    }

    if (username.trim().length < 3) {
      setErrorMessage("Username must contain at least 3 characters.");
      return;
    }

    if (password.length < 6) {
      setErrorMessage("Password must contain at least 6 characters.");
      return;
    }

    setSubmitting(true);
    try {
      await registerUser({
        username: username.trim(),
        email: email.trim(),
        password,
        full_name: fullName.trim() || undefined,
      });

      navigate("/dashboard");
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to register account.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="w-full max-w-[440px] mx-auto z-10 flex flex-col items-center my-auto py-12 sm:py-16 px-4">
      {/* ── Brand Header ── */}
      <div className="flex flex-col items-center text-center mb-6">
        <div className="w-10 h-10 rounded-lg bg-[#111113] border border-[#1e1e22] flex items-center justify-center mb-3 shadow-md">
          <InvertedTriangleLogo />
        </div>

        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#111113] border border-[#1e1e22] mb-3">
          <span className="w-1.5 h-1.5 rounded-full bg-white" />
          <span className="font-mono text-[#a1a1aa] text-[11px] tracking-tight">
            Geist Security · Operator Onboarding
          </span>
        </div>

        <h1 className="text-xl sm:text-2xl font-semibold text-white tracking-tight mb-1">
          Create Account
        </h1>
        <p className="text-xs text-[#71717a] max-w-[340px]">
          Provision your credentials for autonomous security audits and runtime telemetry.
        </p>
      </div>

      {/* ── Main Container ── */}
      <div className="w-full bg-[#0a0a0a] rounded-xl p-6 sm:p-7 shadow-2xl border border-[#1e1e22]">
        {/* ── Error Banner ── */}
        {errorMessage && (
          <div className="mb-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center gap-2.5 text-xs text-red-400 font-mono leading-relaxed">
            <AlertTriangleIcon />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* ── Registration Form ── */}
        <form className="flex flex-col gap-3.5" onSubmit={handleSubmit}>
          {/* Full Name */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono text-[#a1a1aa] flex justify-between items-center" htmlFor="register-fullName">
              <span>Full Name</span>
              <span className="text-[10px] text-[#52525b]">Optional</span>
            </label>
            <input
              id="register-fullName"
              name="fullName"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Alex Morgan"
              className="w-full h-9 px-3 bg-[#111113] text-white placeholder:text-[#52525b] text-xs font-mono rounded-lg border border-[#1e1e22] focus:border-[#71717a] focus:outline-none focus:bg-[#111113] transition-colors"
            />
          </div>

          {/* Username */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono text-[#a1a1aa] flex justify-between items-center" htmlFor="register-username">
              <span>Username</span>
              <span className="text-[10px] text-[#52525b]">Required</span>
            </label>
            <input
              id="register-username"
              name="username"
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="sec_analyst"
              className="w-full h-9 px-3 bg-[#111113] text-white placeholder:text-[#52525b] font-mono text-xs rounded-lg border border-[#1e1e22] focus:border-[#71717a] focus:outline-none focus:bg-[#111113] transition-colors"
            />
          </div>

          {/* Email */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono text-[#a1a1aa] flex justify-between items-center" htmlFor="register-workEmail">
              <span>Email Address</span>
              <span className="text-[10px] text-[#52525b]">Reports &amp; alerts</span>
            </label>
            <input
              id="register-workEmail"
              name="workEmail"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="alex@company.com"
              className="w-full h-9 px-3 bg-[#111113] text-white placeholder:text-[#52525b] font-mono text-xs rounded-lg border border-[#1e1e22] focus:border-[#71717a] focus:outline-none focus:bg-[#111113] transition-colors"
            />
          </div>

          {/* Password & Strength Meter */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono text-[#a1a1aa] flex justify-between items-center" htmlFor="register-passcode">
              <span>Password</span>
              <span className={`text-[11px] font-mono ${currentStrength.labelColor}`}>
                {currentStrength.label}
              </span>
            </label>
            <div className="relative flex items-center">
              <input
                id="register-passcode"
                name="password"
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full h-9 px-3 pr-10 bg-[#111113] text-white placeholder:text-[#52525b] font-mono text-xs rounded-lg border border-[#1e1e22] focus:border-[#71717a] focus:outline-none focus:bg-[#111113] transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute right-2.5 p-1 text-[#52525b] hover:text-[#ededed] transition-colors focus:outline-none"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>

            {/* Discrete Strength Bars */}
            <div className="grid grid-cols-4 gap-1.5 mt-1">
              {currentStrength.barColors.map((colorClass, idx) => (
                <div
                  key={idx}
                  className={`h-1 rounded-full ${colorClass} transition-colors duration-200`}
                />
              ))}
            </div>

            {/* Validation Indicators */}
            <div className="grid grid-cols-2 gap-y-1 gap-x-2 mt-1.5 text-[11px] font-mono select-none">
              <div
                className={`flex items-center gap-1.5 transition-colors ${
                  hasLength ? "text-[#ededed]" : "text-[#52525b]"
                }`}
              >
                <span
                  className={`w-1 h-1 rounded-full ${
                    hasLength ? "bg-white" : "bg-[#27272a]"
                  }`}
                />
                <span>6+ characters</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition-colors ${
                  hasNumber ? "text-[#ededed]" : "text-[#52525b]"
                }`}
              >
                <span
                  className={`w-1 h-1 rounded-full ${
                    hasNumber ? "bg-white" : "bg-[#27272a]"
                  }`}
                />
                <span>1 number</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition-colors ${
                  hasSymbol ? "text-[#ededed]" : "text-[#52525b]"
                }`}
              >
                <span
                  className={`w-1 h-1 rounded-full ${
                    hasSymbol ? "bg-white" : "bg-[#27272a]"
                  }`}
                />
                <span>1 symbol</span>
              </div>
              <div
                className={`flex items-center gap-1.5 transition-colors ${
                  hasEntropy ? "text-[#ededed]" : "text-[#52525b]"
                }`}
              >
                <span
                  className={`w-1 h-1 rounded-full ${
                    hasEntropy ? "bg-white" : "bg-[#27272a]"
                  }`}
                />
                <span>Strong entropy</span>
              </div>
            </div>
          </div>

          {/* Terms Agreement */}
          <div className="flex flex-col gap-2 pt-1">
            <label className="flex items-start gap-2.5 cursor-pointer select-none group">
              <div className="relative flex items-center justify-center mt-0.5">
                <input
                  type="checkbox"
                  checked={agreeTerms}
                  onChange={(e) => setAgreeTerms(e.target.checked)}
                  required
                  className="peer sr-only"
                />
                <div
                  className={`w-3.5 h-3.5 rounded bg-[#111113] border border-[#27272a] flex items-center justify-center transition-colors ${
                    agreeTerms ? "bg-white border-transparent" : "group-hover:border-[#71717a]"
                  }`}
                >
                  {agreeTerms && <CheckIcon />}
                </div>
              </div>
              <span className="text-xs text-[#71717a] group-hover:text-[#a1a1aa] transition-colors leading-relaxed font-sans">
                I agree to the security audit operational guidelines and privacy policies.
              </span>
            </label>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={submitting}
            className="w-full h-9 mt-2 bg-white hover:bg-[#e5e2e1] text-black text-xs font-mono font-semibold rounded-lg flex items-center justify-center gap-1.5 transition-all active:scale-[0.99] shadow-sm cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <span>
              {submitting ? "Registering..." : "Create Account"}
            </span>
            {!submitting && <ArrowIcon />}
          </button>
        </form>

        {/* ── Bottom Redirect Link ── */}
        <div className="mt-5 pt-4 bg-[#111113]/50 -mx-6 sm:-mx-7 -mb-6 sm:-mb-7 px-6 sm:px-7 py-3 flex items-center justify-center gap-1.5 border-t border-[#1e1e22] text-xs font-mono text-[#71717a]">
          <span>Already have an operator account?</span>
          <Link
            to="/login"
            className="text-white hover:underline font-medium transition-colors ml-1"
          >
            Sign In
          </Link>
        </div>
      </div>

      {/* ── Trust Chips ── */}
      <div className="w-full mt-6 pt-1 flex flex-wrap items-center justify-center gap-y-2 gap-x-4 text-center">
        <div className="flex items-center gap-1.5 text-xs font-mono text-[#71717a]">
          <ShieldIcon />
          <span>Non-Destructive AST</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs font-mono text-[#71717a]">
          <LockOpenIcon />
          <span>Salted Hashes</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs font-mono text-[#71717a]">
          <BoltIcon />
          <span>Zero Third-Party SSO</span>
        </div>
      </div>

      {/* ── Security Stamp ── */}
      <div className="mt-4 flex items-center gap-2 px-3 py-1 rounded-full bg-[#111113] border border-[#1e1e22]">
        <span className="w-1.5 h-1.5 rounded-full bg-[#71717a]" />
        <span className="font-mono text-[#71717a] text-[11px] tracking-tight">
          Geist Cryptographic Vault v2.4
        </span>
      </div>
    </div>
  );
}
