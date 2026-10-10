export interface CosmosChainConfig {
  readonly hrp: string;
  readonly coinType: number;
}

export const COSMOS_HUB: CosmosChainConfig = { hrp: "cosmos", coinType: 118 };
export const OSMOSIS: CosmosChainConfig = { hrp: "osmo", coinType: 118 };
export const TERRA: CosmosChainConfig = { hrp: "terra", coinType: 330 };
export const JUNO: CosmosChainConfig = { hrp: "juno", coinType: 118 };
export const SECRET: CosmosChainConfig = { hrp: "secret", coinType: 529 };
export const KAVA: CosmosChainConfig = { hrp: "kava", coinType: 459 };

export function cosmosChainConfig(hrp: string, coinType: number): CosmosChainConfig {
  return { hrp, coinType };
}

export function cosmosPath(coinType: number, index: number): string {
  return `m/44'/${coinType}'/0'/0/${index}`;
}
