import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
  input: "../api/openapi.json",
  output: "./lib/api",
  plugins: [
    "@hey-api/typescript",
    {
      name: "@hey-api/client-fetch",
      bundle: true,
    },
    {
      name: "@hey-api/sdk",
    },
  ],
});
