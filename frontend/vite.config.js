import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// base './' => asset URLs stay relative so the bundle works both at the
// domain root and under a sub-path.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true },
  server: { port: 5173, proxy: { "/api": "http://localhost:9000", "/health": "http://localhost:9000" } },
});
