import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are committed into the orchestrator's static directory, so
// running Kleos needs Python and nothing else: Node is a development dependency
// of this directory, not of the service.
//
// `base` has to match where the orchestrator serves this from, because the
// index page references its assets by absolute path and the orchestrator mounts
// them at /ui/assets.
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "../orchestrator/src/orchestrator/static/ui",
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` serves the UI on its own port, where it is *not* same-origin
    // with the orchestrator -- and the orchestrator deliberately has no CORS
    // middleware. So dev proxies the orchestrator's routes through this origin
    // rather than asking the service to relax, which would be the one change
    // most likely to make the owner-authenticated routes reachable from
    // elsewhere. The gateway needs no proxy: it already allows any origin.
    proxy: {
      "/memory": "http://127.0.0.1:8090",
      "/query": "http://127.0.0.1:8090",
      "/explorer": "http://127.0.0.1:8090",
    },
  },
});
