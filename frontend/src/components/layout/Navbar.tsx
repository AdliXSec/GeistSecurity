import React, { useState, useEffect, useRef } from "react";
import { NavLink, Link, useNavigate } from "react-router-dom";
import { ChevronDown, ChevronsUpDown, LogOut, User as UserIcon } from "lucide-react";
import { getStoredUser, clearStoredAuth, type UserProfile } from "../../lib/api";

export const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => getStoredUser());
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Sync user state on window storage events
  useEffect(() => {
    const handleStorage = () => {
      setCurrentUser(getStoredUser());
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
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
    navigate("/login");
  };

  const userInitials = currentUser?.username
    ? currentUser.username.slice(0, 2).toUpperCase()
    : "OP";

  return (
    <header className="h-14 sticky top-0 z-50 bg-black/80 backdrop-blur-md border-b border-[#1e1e22]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-full flex items-center justify-between">
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
              <span className="text-[#3f3f46] select-none">/</span>
              <button
                type="button"
                className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-normal text-[#a1a1aa] hover:text-white hover:bg-[#161618] transition-colors focus:outline-none"
              >
                <span>{currentUser.username}</span>
                <ChevronsUpDown size={14} className="text-[#71717a]" />
              </button>
            </>
          )}
        </div>

        {/* Center navigation */}
        <nav className="hidden md:flex items-center gap-1">
          {[
            { to: "/dashboard", label: "Dashboard" },
            { to: "/audit/new", label: "New Audit" },
            { to: "/docs", label: "Documentation" },
          ].map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `px-3 py-1.5 rounded-md text-xs font-mono transition-colors ${
                  isActive
                    ? "text-white bg-[#161618] font-medium"
                    : "text-[#a1a1aa] hover:text-white hover:bg-[#161618]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        {/* Right */}
        <div className="flex items-center gap-3">
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

                {/* User Dropdown Menu */}
                {showDropdown && (
                  <div className="absolute right-0 mt-2 w-56 rounded-xl bg-[#0a0a0a] border border-[#1e1e22] shadow-2xl py-1.5 z-50">
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
            <div className="flex items-center gap-2">
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
        </div>
      </div>
    </header>
  );
};

export default Navbar;
