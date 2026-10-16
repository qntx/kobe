declare const __qntx: {
  readonly random: (length: number) => Uint8Array;
  readonly now: () => number;
  readonly elapsed: () => number;
  readonly setTimer: (delayMs: number, fn: () => void) => () => void;
  readonly post: (message: ArrayBuffer) => void;
  readonly setMessageHandler: (fn: (message: ArrayBuffer) => void) => void;
  readonly pbkdf2: (
    hash: "sha256" | "sha512",
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    length: number,
    done: (result: Uint8Array | undefined, error: string | undefined) => void,
  ) => void;
};

declare const NitroModulesProxy:
  | {
      readonly createHybridObject: (name: string) => {
        readonly publicKey: (secretKey: ArrayBuffer) => ArrayBuffer;
        readonly sign: (id: ArrayBuffer, secretKey: ArrayBuffer, auxRand: ArrayBuffer) => ArrayBuffer;
        readonly verifySerialized: (
          serializedUtf8: ArrayBuffer,
          id: ArrayBuffer,
          pubkey: ArrayBuffer,
          sig: ArrayBuffer,
        ) => boolean;
      };
    }
  | undefined;

declare const HermesInternal:
  | {
      readonly getRuntimeProperties?: () => Record<string, string>;
    }
  | undefined;
