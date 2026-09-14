import { useLocation, useNavigate, Link } from "react-router-dom";
import { useEffect } from "react";
import { Shield, ArrowLeft } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border flex items-center justify-between px-6 py-4">
        <Link to="/" className="flex items-center gap-[5px]">
          <Shield className="h-7 w-7 text-primary" />
          <span className="font-sans text-xl font-bold tracking-[-0.5px] text-foreground">BlackShield</span>
        </Link>
        <Link to={user ? "/dashboard" : "/auth"} className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          {user ? "Dashboard" : "Log in"}
        </Link>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-24">
        <div className="w-full max-w-lg flex flex-col items-center text-center">
          <span className="border border-border rounded text-[12px] font-mono text-muted-foreground px-3 py-1 mb-4">HTTP 404</span>

          <div className="w-full bg-[#08090c] border border-border rounded-lg p-5 flex flex-col gap-2 text-left mb-8">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-destructive/70" />
              <span className="font-mono text-xs text-muted-foreground">request.log</span>
            </div>
            <pre className="font-mono text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed">
              <span className="text-foreground">GET</span> {location.pathname} <span className="text-destructive">404 Not Found</span>{"\n"}
              reason: route does not exist or has been moved{"\n"}
              status: no scan or resource affected
            </pre>
          </div>

          <h1 className="text-2xl font-semibold text-foreground mb-2">This page doesn't exist</h1>
          <p className="text-sm text-muted-foreground max-w-md mb-8">
            The page you're looking for may have been moved, renamed, or the link you followed is out of date. Nothing on your account has changed.
          </p>

          <div className="flex gap-3 mb-10">
            <button
              onClick={() => navigate(user ? "/dashboard" : "/")}
              className="flex items-center gap-1.5 bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-5 py-2.5 rounded-md transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> {user ? "Return to dashboard" : "Go to homepage"}
            </button>
            {user && (
              <Link to="/" className="border border-border text-foreground text-sm font-medium px-5 py-2.5 rounded-md hover:bg-muted/30 transition-colors">
                Go to homepage
              </Link>
            )}
          </div>

          <div className="border-t border-border pt-6 w-full flex flex-col items-center gap-3">
            <p className="text-xs text-muted-foreground">Looking for something specific?</p>
            <div className="flex gap-2">
              <Link to="/dashboard/tools" className="border border-border text-xs text-muted-foreground hover:text-foreground px-3 py-1.5 rounded transition-colors">Tools directory</Link>
              <Link to="/docs" className="border border-border text-xs text-muted-foreground hover:text-foreground px-3 py-1.5 rounded transition-colors">Documentation</Link>
              <a href="mailto:support@blackshield.dev" className="border border-border text-xs text-muted-foreground hover:text-foreground px-3 py-1.5 rounded transition-colors">Support</a>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default NotFound;
