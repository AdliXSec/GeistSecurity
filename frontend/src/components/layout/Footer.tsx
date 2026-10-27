import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Shield, Check, ExternalLink } from "lucide-react";

export interface FooterProps {
  variant?: "minimal" | "full";
  className?: string;
}

export const Footer: React.FC<FooterProps> = ({ variant = "full", className = "" }) => {
  const [email, setEmail] = useState("");
  const [subscribed, setSubscribed] = useState(false);

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim()) {
      setSubscribed(true);
      setTimeout(() => {
        setEmail("");
      }, 3000);
    }
  };

  // If minimal is explicitly requested, render a clean, high-signal single-row status bar
  if (variant === "minimal") {
    return (
      <footer className={`border-t border-[#1e1e22] bg-black print:hidden ${className}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#71717a]">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_#10b981]" />
            <span className="text-[#ededed]">All systems operational</span>
            <span>·</span>
            <span>Cluster latency 14ms</span>
            <span className="hidden md:inline">·</span>
            <span className="hidden md:inline">Zero-Data Plaintext Retention</span>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-[#71717a]">
            <Link to="/docs" className="hover:text-white transition-colors">
              Documentation
            </Link>
            <Link to="/dashboard" className="hover:text-white transition-colors">
              Dashboard
            </Link>
            <Link to="/audit/new" className="hover:text-white transition-colors">
              New Audit
            </Link>
            <span>© 2026 Geist Security</span>
          </div>
        </div>
      </footer>
    );
  }

  // Consistent enterprise full footer across all application views
  return (
    <footer className={`border-t border-[#1e1e22] bg-[#000000] print:hidden ${className}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Top section: Brand, Slogan, and Newsletter */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 pb-10 border-b border-[#1e1e22]">
          <div className="lg:col-span-6 space-y-3">
            <Link to="/" className="inline-flex items-center gap-2">
              <svg viewBox="0 0 24 24" className="h-5 w-5 text-white fill-current">
                <path d="M12 22L2 4.5h20L12 22z" />
              </svg>
              <span className="text-sm font-semibold text-white tracking-tight">Geist Security</span>
              <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-[#111113] border border-[#1e1e22] text-[#a1a1aa]">
                v1.4.0
              </span>
            </Link>
            <p className="text-xs text-[#a1a1aa] font-mono leading-relaxed max-w-lg">
              Autonomous Web &amp; Code Security Audits Before Adversaries Strike.
            </p>
            <p className="text-[11px] text-[#71717a] font-mono leading-relaxed max-w-lg">
              Combining active DAST vulnerability probing, AST taint tracing, secret mining, and AI-driven automated remediation for modern engineering teams.
            </p>
          </div>

          <div className="lg:col-span-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-white mb-1.5">
                <Shield className="w-3.5 h-3.5 text-[#ededed]" />
                <span>Security Intelligence Digest</span>
              </div>
              <p className="text-xs font-mono text-[#71717a] mb-3">
                Subscribe for real-time zero-day advisories, OWASP heuristics, and engine rule updates.
              </p>
            </div>

            <form onSubmit={handleSubscribe} className="space-y-2">
              <div className="flex gap-2 max-w-md">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="security-team@acme.com"
                  required
                  className="flex-1 h-8 px-3 text-xs bg-[#0a0a0a] border border-[#1e1e22] rounded-md text-white placeholder-[#71717a] font-mono focus:outline-none focus:border-[#3f3f46] transition-colors"
                />
                <button
                  type="submit"
                  className="h-8 px-4 text-xs font-mono font-medium bg-white text-black rounded-md hover:bg-[#ededed] transition-colors flex items-center gap-1.5 shrink-0"
                >
                  {subscribed ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Subscribed</span>
                    </>
                  ) : (
                    <span>Subscribe</span>
                  )}
                </button>
              </div>
              {subscribed && (
                <p className="text-[11px] text-emerald-400 font-mono flex items-center gap-1">
                  <Check className="w-3 h-3" />
                  <span>Subscribed to zero-day security advisories feed.</span>
                </p>
              )}
            </form>
          </div>
        </div>

        {/* Middle section: Navigation columns */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-8 py-10">
          <div>
            <h3 className="text-xs font-semibold text-white mb-3 tracking-tight font-mono uppercase text-[11px]">
              Platform &amp; Audits
            </h3>
            <ul className="space-y-2">
              <li>
                <Link to="/dashboard" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Security Audits
                </Link>
              </li>
              <li>
                <Link to="/audit/new" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Configure Audit
                </Link>
              </li>
              <li>
                <Link to="/audit/progress/demo-fintech" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Telemetry Stream
                </Link>
              </li>
              <li>
                <Link to="/audit/report/demo-fintech" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Audit Reports
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-xs font-semibold text-white mb-3 tracking-tight font-mono uppercase text-[11px]">
              Security Engines
            </h3>
            <ul className="space-y-2">
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Nuclei Active DAST
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  AST Taint Tracing
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Shannon Secret Mining
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  OSV CVE Reachability
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-xs font-semibold text-white mb-3 tracking-tight font-mono uppercase text-[11px]">
              Developers &amp; CLI
            </h3>
            <ul className="space-y-2">
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Documentation
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  REST API Reference
                </Link>
              </li>
              <li>
                <Link to="/" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  System Architecture
                </Link>
              </li>
              <li>
                <a
                  href="https://github.com/projectdiscovery/nuclei"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs font-mono text-[#71717a] hover:text-white transition-colors inline-flex items-center gap-1"
                >
                  <span>Curated Rulesets</span>
                  <ExternalLink className="w-3 h-3 text-[#52525b]" />
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="text-xs font-semibold text-white mb-3 tracking-tight font-mono uppercase text-[11px]">
              Compliance &amp; Trust
            </h3>
            <ul className="space-y-2">
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Zero-Data Retention
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Responsible Disclosure
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Terms of Service
                </Link>
              </li>
              <li>
                <Link to="/docs" className="text-xs font-mono text-[#71717a] hover:text-white transition-colors">
                  Privacy Policy
                </Link>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom bar: Status, latency, and copyright */}
        <div className="border-t border-[#1e1e22] pt-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-[#71717a]">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_#10b981]" />
            <span className="text-[#ededed]">All systems operational</span>
            <span>·</span>
            <span>Cluster latency 14ms</span>
            <span className="hidden md:inline">·</span>
            <span className="hidden md:inline text-[#a1a1aa]">Non-destructive AST testing</span>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono text-[#71717a]">
            <span>© 2026 Geist Security. All rights reserved.</span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
