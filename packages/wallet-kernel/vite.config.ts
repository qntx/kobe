import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

// No build step: the kernel is bundled by the host packages, never packed.
const config: UserConfig = defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
});

export default config;
