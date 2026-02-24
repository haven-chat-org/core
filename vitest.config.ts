import { defineConfig } from "vitest/config";
import { resolve } from "path";

export default defineConfig({
  resolve: {
    alias: {
      // libsodium-wrappers-sumo ESM build references a missing file.
      // Alias to the CJS build which works fine under vitest/Node.
      "libsodium-wrappers-sumo": resolve(
        __dirname,
        "node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js",
      ),
    },
  },
});
