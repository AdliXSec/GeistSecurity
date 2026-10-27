import React from "react";
import { Outlet } from "react-router-dom";
import { Navbar } from "./Navbar";
import { Footer } from "./Footer";

interface LayoutProps {
  footerVariant?: "minimal" | "full";
}

export const Layout: React.FC<LayoutProps> = ({ footerVariant = "full" }) => {
  return (
    <div className="min-h-screen flex flex-col bg-black font-sans text-[#ededed] antialiased">
      <Navbar />
      <main className="flex-1 relative z-10 flex flex-col">
        <Outlet />
      </main>
      <Footer variant={footerVariant} />
    </div>
  );
};

export default Layout;
