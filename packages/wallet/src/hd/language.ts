import { DeriveError } from "../errors/derive.ts";

/** BIP-39 languages shipped by `@scure/bip39`. */
export type MnemonicLanguage =
  | "english"
  | "japanese"
  | "korean"
  | "spanish"
  | "french"
  | "italian"
  | "czech"
  | "portuguese"
  | "simplified-chinese"
  | "traditional-chinese";

export const MNEMONIC_LANGUAGES: readonly MnemonicLanguage[] = [
  "english",
  "japanese",
  "korean",
  "spanish",
  "french",
  "italian",
  "czech",
  "portuguese",
  "simplified-chinese",
  "traditional-chinese",
];

const ACCEPTED = [
  "english",
  "en",
  "japanese",
  "ja",
  "jp",
  "korean",
  "ko",
  "kr",
  "spanish",
  "es",
  "french",
  "fr",
  "italian",
  "it",
  "czech",
  "cs",
  "cz",
  "portuguese",
  "pt",
  "simplified-chinese",
  "chinese-simplified",
  "zh-hans",
  "zh-cn",
  "traditional-chinese",
  "chinese-traditional",
  "zh-hant",
  "zh-tw",
] as const;

/** Case-insensitive alias parse. Unknown token → DeriveError input. */
export function parseMnemonicLanguage(token: string): MnemonicLanguage {
  switch (token.trim().toLowerCase()) {
    case "english":
    case "en":
      return "english";
    case "japanese":
    case "ja":
    case "jp":
      return "japanese";
    case "korean":
    case "ko":
    case "kr":
      return "korean";
    case "spanish":
    case "es":
      return "spanish";
    case "french":
    case "fr":
      return "french";
    case "italian":
    case "it":
      return "italian";
    case "czech":
    case "cs":
    case "cz":
      return "czech";
    case "portuguese":
    case "pt":
      return "portuguese";
    case "simplified-chinese":
    case "chinese-simplified":
    case "zh-hans":
    case "zh-cn":
      return "simplified-chinese";
    case "traditional-chinese":
    case "chinese-traditional":
    case "zh-hant":
    case "zh-tw":
      return "traditional-chinese";
    default:
      throw new DeriveError(
        "input",
        `unknown mnemonic language '${token}' (accepted: ${ACCEPTED.join(", ")})`,
      );
  }
}
