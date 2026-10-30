import React, { useState, useEffect, useRef } from "react";
import { NavLink, Link, useNavigate, useLocation } from "react-router-dom";
import {
  ChevronDown,
  ChevronsUpDown,
  LogOut,
  User as UserIcon,
  Menu,
  X,
  Shield,
  Plus,
  BookOpen,
  LayoutDashboard,
} from "lucide-react";
import { getStoredUser, clearStoredAuth, type UserProfile } from "../../lib/api";

export const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => getStoredUser());
  const [showDropdown, setShowDropdown] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const prevPathRef = useRef(location.pathname);
  useEffect(() => {
    if (prevPathRef.current !== location.pathname) {
      prevPathRef.current = location.pathname;
      setMobileMenuOpen(false);
      setShowDropdown(false);
      // Safety net: re-read auth on every route change
      setCurrentUser(getStoredUser());
    }
  }, [location.pathname]);

  // Sync user state: 'auth-change' = same tab (login/logout/register), 'storage' = other tabs
  useEffect(() => {
    const syncUser = () => setCurrentUser(getStoredUser());
    window.addEventListener("auth-change", syncUser);
    window.addEventListener("storage", syncUser);
    return () => {
      window.removeEventListener("auth-change", syncUser);
      window.removeEventListener("storage", syncUser);
    };
  }, []);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = () => {
    clearStoredAuth();
    setCurrentUser(null);
    setShowDropdown(false);
    setMobileMenuOpen(false);
    navigate("/login");
  };

  const userInitials = currentUser?.username
    ? currentUser.username.slice(0, 2).toUpperCase()
    : "OP";

  const navLinks = [
    { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { to: "/audit/new", label: "New Audit", icon: Plus },
    { to: "/docs", label: "Documentation", icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-50 bg-black/85 backdrop-blur-md border-b border-[#1e1e22]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        {/* Left */}
        <div className="flex items-center gap-2.5 text-sm font-medium tracking-tight">
          <NavLink to="/" className="flex items-center gap-2 text-white hover:opacity-90 transition-opacity">
            <svg viewBox="0 0 24 24" className="h-5 w-5 text-white fill-current">
              <path d="M12 22L2 4.5h20L12 22z" />
            </svg>
            <span className="text-sm font-medium tracking-tight text-white">Geist Security</span>
          </NavLink>
          {currentUser && (
            <>
              <span className="text-[#3f3f46] select-none hidden sm:inline">/</span>
              <button
                type="button"
                className="hidden sm:flex items-center gap-1 px-2 py-1 rounded-md text-xs font-normal text-[#a1a1aa] hover:text-white hover:bg-[#161618] transition-colors focus:outline-none"
              >
                <span className="truncate max-w-[120px]">{currentUser.username}</span>
                <ChevronsUpDown size={14} className="text-[#71717a] shrink-0" />
              </button>
            </>
          )}
        </div>

        {/* Center desktop navigation */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `px-3 py-1.5 rounded-md text-xs font-mono transition-colors ${
                  isActive
                    ? "text-white bg-[#161618] font-medium border border-[#27272a]"
                    : "text-[#a1a1aa] hover:text-white hover:bg-[#161618]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        {/* Right (Desktop and Mobile Controls) */}
        <div className="flex items-center gap-2 sm:gap-3">
          {currentUser ? (
            <>
              <Link
                to="/audit/new"
                className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-medium bg-white text-black hover:bg-[#ededed] transition-colors"
              >
                <span>Launch Audit</span>
              </Link>
              <div className="relative" ref={dropdownRef}>
                <button
                  type="button"
                  onClick={() => setShowDropdown((prev) => !prev)}
                  className="flex items-center gap-1.5 py-1 px-1.5 rounded-lg hover:bg-[#161618] transition-colors focus:outline-none"
                  title={`${currentUser.username} (${currentUser.email})`}
                >
                  <div className="w-7 h-7 rounded-full bg-[#27272a] border border-[#3f3f46] font-mono text-[11px] text-white flex items-center justify-center">
                    {userInitials}
                  </div>
                  <ChevronDown size={12} className="text-[#71717a] hidden sm:block" />
                </button>

                {/* Desktop User Dropdown Menu */}
                {showDropdown && (
                  <div className="absolute right-0 mt-2 w-56 rounded-xl bg-[#0a0a0a] border border-[#1e1e22] shadow-2xl py-1.5 z-50 animate-in fade-in zoom-in-95 duration-100">
                    <div className="px-3.5 py-2 border-b border-[#1e1e22]">
                      <p className="text-xs font-semibold text-[#ededed] truncate">
                        {currentUser.full_name || currentUser.username}
                      </p>
                      <p className="text-[11px] font-mono text-[#71717a] truncate mt-0.5">
                        {currentUser.email}
                      </p>
                    </div>

                    <div className="py-1">
                      <Link
                        to="/dashboard"
                        onClick={() => setShowDropdown(false)}
                        className="w-full flex items-center gap-2 px-3.5 py-2 text-xs text-[#a1a1aa] hover:text-[#ededed] hover:bg-[#161618] transition-colors"
                      >
                        <UserIcon size={14} />
                        <span>Security Workspace</span>
                      </Link>

                      <button
                        type="button"
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3.5 py-2 text-xs text-[#ef4444] hover:bg-[#ef4444]/10 transition-colors text-left"
                      >
                        <LogOut size={14} />
                        <span>Sign Out</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="hidden sm:flex items-center gap-2">
              <Link
                to="/login"
                className="px-2.5 py-1 text-xs font-mono text-[#a1a1aa] hover:text-[#ededed] transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="px-3 py-1 rounded-md text-xs font-mono font-medium bg-white text-black hover:bg-[#ededed] transition-colors"
              >
                Sign Up
              </Link>
            </div>
          )}

          {/* Mobile Menu Hamburger Button (visible on mobile only) */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
            className="md:hidden flex items-center justify-center p-2 rounded-lg text-[#a1a1aa] hover:text-white hover:bg-[#161618] transition-colors focus:outline-none"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Drawer / Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-[#1e1e22] bg-[#0a0a0a]/95 backdrop-blur-xl px-4 py-4 space-y-4 animate-in slide-in-from-top-2 duration-150">
          {/* Navigation Links */}
          <div className="flex flex-col space-y-1">
            {navLinks.map((link) => {
              const Icon = link.icon;
              return (
                <NavLink
                  key={link.to}
                  to={link.to}
                  onClick={() => setMobileMenuOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-mono transition-colors ${
                      isActive
                        ? "text-white bg-[#161618] border border-[#27272a] font-medium"
                        : "text-[#a1a1aa] hover:text-white hover:bg-[#161618]"
                    }`
                  }
                >
                  <Icon size={16} className="text-[#71717a]" />
                  <span>{link.label}</span>
                </NavLink>
              );
            })}
          </div>

          {/* Quick Action Button */}
          <div className="pt-2 border-t border-[#1e1e22]">
            <Link
              to="/audit/new"
              onClick={() => setMobileMenuOpen(false)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono font-semibold bg-white text-black hover:bg-[#ededed] transition-colors shadow-sm"
            >
              <Shield size={14} />
              <span>Launch New Audit</span>
            </Link>
          </div>

          {/* Auth section on Mobile */}
          <div className="pt-2 border-t border-[#1e1e22]">
            {currentUser ? (
              <div className="flex items-center justify-between py-1">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="w-7 h-7 rounded-full bg-[#27272a] border border-[#3f3f46] font-mono text-[11px] text-white flex items-center justify-center shrink-0">
                    {userInitials}
                  </div>
                  <div className="flex flex-col min-w-0">
                    <span className="text-xs font-semibold text-white truncate">
                      {currentUser.username}
                    </span>
                    <span className="text-[10px] font-mono text-[#71717a] truncate">
                      {currentUser.email}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono text-red-400 hover:bg-red-950/30 transition-colors shrink-0"
                >
                  <LogOut size={13} />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-2">
                <Link
                  to="/login"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex items-center justify-center py-2 rounded-lg text-xs font-mono text-[#ededed] bg-[#161618] border border-[#1e1e22] hover:bg-[#1f1f23] transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  onClick={() => setMobileMenuOpen(false)}
                  className="flex items-center justify-center py-2 rounded-lg text-xs font-mono font-medium text-black bg-white hover:bg-[#ededed] transition-colors"
                >
                  Sign Up
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </header>
  );
};

export default Navbar;
