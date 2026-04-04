import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    // Use "/api/" so "/api-pen-test" (SPA route) is NOT proxied to the backend.
    proxy: {
      "/api/": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
