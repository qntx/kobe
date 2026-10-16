import type { ExpoConfig } from "expo/config";

const config = (): ExpoConfig => ({
  name: "V1 Harness",
  slug: "qntx-wallet-harness",
  version: "0.0.0",
  orientation: "portrait",
  userInterfaceStyle: "light",
  ios: {
    bundleIdentifier: "org.qntx.wallet.harness",
    supportsTablet: false,
    appleTeamId: "6Z33CD4837",
  },
  android: {
    package: "org.qntx.wallet.harness",
  },
});

export default config;
