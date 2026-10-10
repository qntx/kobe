import { DeriveError } from "../../errors/derive.ts";

export type BtcNetwork = "mainnet" | "testnet";
export type BtcAddressType = "p2pkh" | "p2sh-p2wpkh" | "p2wpkh" | "p2tr";

export function parseBtcNetwork(token: string): BtcNetwork {
  switch (token.trim().toLowerCase()) {
    case "mainnet":
    case "main":
    case "bitcoin":
      return "mainnet";
    case "testnet":
    case "test":
    case "testnet3":
    case "testnet4":
      return "testnet";
    default:
      throw new DeriveError("input", "invalid network, expected: mainnet or testnet");
  }
}

export function parseBtcAddressType(token: string): BtcAddressType {
  switch (token.trim().toLowerCase()) {
    case "p2pkh":
    case "legacy":
      return "p2pkh";
    case "p2sh":
    case "p2sh-p2wpkh":
    case "segwit":
    case "nested-segwit":
      return "p2sh-p2wpkh";
    case "p2wpkh":
    case "native-segwit":
    case "bech32":
      return "p2wpkh";
    case "p2tr":
    case "taproot":
    case "bech32m":
      return "p2tr";
    default:
      throw new DeriveError(
        "input",
        "invalid address type, expected: p2pkh, p2sh, p2wpkh, or p2tr",
      );
  }
}

const BTC_PURPOSES: Record<BtcAddressType, number> = {
  p2pkh: 44,
  "p2sh-p2wpkh": 49,
  p2wpkh: 84,
  p2tr: 86,
};

export function btcPurpose(type: BtcAddressType): number {
  return BTC_PURPOSES[type];
}

export function btcCoinType(network: BtcNetwork): number {
  return network === "mainnet" ? 0 : 1;
}

export function addressTypeFromPurpose(purpose: number): BtcAddressType | undefined {
  switch (purpose) {
    case 44:
      return "p2pkh";
    case 49:
      return "p2sh-p2wpkh";
    case 84:
      return "p2wpkh";
    case 86:
      return "p2tr";
    default:
      return undefined;
  }
}

export function btcPath(
  type: BtcAddressType,
  network: BtcNetwork,
  index: number,
  account = 0,
  change = false,
): string {
  const purpose = btcPurpose(type);
  const coin = btcCoinType(network);
  const ch = change ? 1 : 0;
  return `m/${purpose}'/${coin}'/${account}'/${ch}/${index}`;
}
