import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

export default defineConfig({
  server: {
    host: true,
    port: 8080,
    hmr: { overlay: false },
    proxy: {
      "/api/sslanalyzer":              { target: "http://localhost:8765", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/sslanalyzer/, "") },
      "/api/auth":                     { target: "http://localhost:8766", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/chat":                     { target: "http://localhost:8000", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/chat/, "/chat") },
      "/api/health":                   { target: "http://localhost:8000", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/health/, "/health") },
      "/api/firewall":                 { target: "http://localhost:8777", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/portscan":                 { target: "http://localhost:5017", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/portscan/, "/portscan") },
      "/api/network/analyze":          { target: "http://localhost:5018", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/network\/analyze/, "/network/analyze") },
      "/api/gobuster":                 { target: "http://localhost:8767", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/gobuster/, "") },
      "/api/sqlmap":                   { target: "http://localhost:8768", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/sqlmap/, "") },
      "/api/network/network":          { target: "http://localhost:8775", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/network\/network/, ""), },
      "/api/nmap":                     { target: "http://localhost:8773", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/nmap/, "") },
      "/api/ddos":                     { target: "http://localhost:8775", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/password":                 { target: "http://localhost:8778", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/cve":                      { target: "http://localhost:8779", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/ssl":                      { target: "http://localhost:8776", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
      "/api/activity":                 { target: "http://localhost:8781", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/activity/, "") },
      "/api/ctf":                      { target: "http://localhost:8782", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/ctf/, "") },
      "/api/assistant":                { target: "http://localhost:8783", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/assistant/, "") },
      "/api/scenarios":                { target: "http://localhost:8784", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/scenarios/, "") },
      "/api/sniper":                   { target: "http://localhost:8769", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/sniper/, "") },
      "/api/subdomain":                { target: "http://localhost:8770", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/subdomain/, "") },
      "/api/hashcat":                  { target: "http://localhost:8771", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/hashcat/, "") },
      "/api/metasploit":               { target: "http://localhost:8772", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/metasploit/, "") },
      "/api/ids":                      { target: "http://localhost:8774", changeOrigin: true, rewrite: (p) => p.replace(/^\/api\/ids/, "") },
    },
  },
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
});
