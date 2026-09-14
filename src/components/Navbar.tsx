import { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { Shield, Menu, X } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const onHome = location.pathname === "/";

  const handleHomeClick = () => {
    setMobileOpen(false);
    if (window.location.pathname !== "/") {
      navigate("/");
      setTimeout(() => window.scrollTo({ top: 0, behavior: "smooth" }), 100);
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  const handleServicesClick = () => {
    setMobileOpen(false);
    if (window.location.pathname !== "/") {
      navigate("/");
      setTimeout(() => document.getElementById("services")?.scrollIntoView({ behavior: "smooth" }), 100);
    } else {
      document.getElementById("services")?.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <nav className="fixed top-0 left-0 right-0 z-40 bg-[rgba(10,13,18,0.95)] backdrop-blur-md border-b border-border">
      <div className="container mx-auto flex items-center justify-between h-[62px] px-6">

        {/* Logo */}
        <button onClick={handleHomeClick} className="flex items-center gap-[5px]">
          <Shield className="h-7 w-7 text-primary" />
          <span className="font-sans text-xl font-bold tracking-[-0.5px] text-foreground">BlackShield</span>
        </button>

        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-8">
          <button onClick={handleHomeClick} className="relative self-stretch flex items-center text-sm font-medium text-foreground">
            Platform
            {onHome && (
              <span className="absolute -bottom-[17px] left-0 right-0 h-[2px] bg-primary" />
            )}
          </button>
          <button onClick={handleServicesClick} className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
            Services
          </button>
          <Link to="/docs" onClick={() => setMobileOpen(false)} className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
            Docs
          </Link>
        </div>

        {/* Right actions */}
        <div className="hidden md:flex items-center gap-4">
          {user ? (
            <Link to="/dashboard" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
              Log in
            </Link>
          ) : (
            <Link to="/auth" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
              Log in
            </Link>
          )}
          <Link
            to={user ? "/dashboard" : "/auth"}
            className="bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-4 py-2 rounded-md transition-colors"
          >
            {user ? "Dashboard" : "Get Started"}
          </Link>
        </div>

        {/* Mobile Toggle */}
        <button className="md:hidden text-foreground" onClick={() => setMobileOpen(!mobileOpen)}>
          {mobileOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden bg-[rgba(10,13,18,0.98)] border-t border-border p-4 space-y-3">
          <button onClick={handleHomeClick} className="block w-full text-left text-sm font-medium text-foreground">
            Platform
          </button>
          <button onClick={handleServicesClick} className="block w-full text-left text-sm text-muted-foreground hover:text-foreground">
            Services
          </button>
          <Link to="/docs" onClick={() => setMobileOpen(false)} className="block w-full text-left text-sm text-muted-foreground hover:text-foreground">
            Docs
          </Link>
          <Link to={user ? "/dashboard" : "/auth"} onClick={() => setMobileOpen(false)} className="block w-full text-left text-sm text-muted-foreground hover:text-foreground">
            Log in
          </Link>
          <Link to={user ? "/dashboard" : "/auth"} onClick={() => setMobileOpen(false)}>
            <span className="block w-full text-center bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-4 py-2 rounded-md transition-colors">
              {user ? "Dashboard" : "Get Started"}
            </span>
          </Link>
        </div>
      )}
    </nav>
  );
}
