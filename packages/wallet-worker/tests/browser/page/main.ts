import type { UnsignedEvent } from "@qntx/nostr";
import { WalletError } from "@qntx/wallet";
import type { MnemonicDraft, NostrKeyRef, Wallet, WalletOptions } from "@qntx/wallet";
/**
 * The minimal test page for the Web host Playwright suite. It patches `Worker` for a spawn/
 * terminate counter (a page-side test hook — the library itself stays uninstrumented) and exposes a
 * small `window.qntx` API over the real wallet. Fallible calls return `{ ok, code }` because thrown
 * WalletError instances do not survive page.evaluate serialization with their `code`.
 */
import { createWebWallet } from "@qntx/wallet-worker/browser";
import { nostr } from "@qntx/wallet/nostr";

const stats = { spawned: 0, terminated: 0 };
const NativeWorker = Worker;
Object.assign(globalThis, {
  Worker: class extends NativeWorker {
    constructor(url: string | URL, options?: WorkerOptions) {
      super(url, options);
      stats.spawned += 1;
    }
    override terminate(): void {
      stats.terminated += 1;
      super.terminate();
    }
  },
});

const OPTIONS: WalletOptions = {
  passkey: {
    rpId: "localhost",
    rpName: "localhost",
    walletSalt: "qntx/wallet",
    vaultSalt: "qntx/vault",
  },
  autoLock: { platform: "web", idleMinutes: 15 },
};

let wallet: Wallet | undefined;
let draft: MnemonicDraft | undefined;

function current(): Wallet {
  if (wallet === undefined) {
    throw new Error("wallet not created");
  }
  return wallet;
}

type CallResult<T = unknown> =
  | { readonly ok: true; readonly value: T }
  | {
      readonly ok: false;
      readonly code: string;
    };

async function attempt<T>(fn: () => Promise<T>): Promise<CallResult<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    return {
      ok: false,
      code: error instanceof WalletError ? error.code : `unknown:${String(error)}`,
    };
  }
}

type StoredRow = { readonly kind: string; readonly header: string; [key: string]: unknown };

/** IDB requests resolve with `any`; the row shape is fixed by this store's writers. */
async function requestResult<T>(request: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    request.addEventListener("success", () => {
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- see above
      resolve(request.result as T);
    });
    request.addEventListener("error", () => {
      reject(new Error("indexeddb request failed", { cause: request.error }));
    });
  });
}

/** Flips `backup` on the first entropy record's header, then pokes the store watch channel. */
async function tamperBackup(): Promise<{ readonly flipped: boolean }> {
  const db = await requestResult<IDBDatabase>(indexedDB.open("qntx-wallet", 1));
  const tx = db.transaction("records", "readwrite");
  const rows = await requestResult<StoredRow[]>(tx.objectStore("records").getAll());
  const entropy = rows.find((row) => row.kind === "entropy");
  if (entropy === undefined) {
    return { flipped: false };
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- JSON.parse is untyped
  const header = JSON.parse(entropy.header) as { backup?: string };
  header.backup = header.backup === "none" ? "passkey" : "none";
  await requestResult(
    tx.objectStore("records").put({ ...entropy, header: JSON.stringify(header) }),
  );
  // oxlint-disable-next-line unicorn/require-post-message-target-origin -- BroadcastChannel takes no targetOrigin
  new BroadcastChannel("qntx-wallet").postMessage("changed");
  return { flipped: true };
}

/** Awaits the transaction's `complete` event — request success alone precedes commit. */
async function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.addEventListener("complete", () => {
      resolve();
    });
    tx.addEventListener("abort", () => {
      reject(new Error("indexeddb transaction aborted"));
    });
    tx.addEventListener("error", () => {
      reject(new Error("indexeddb transaction failed", { cause: tx.error }));
    });
  });
}

/** Writes a record row whose `sealed` is a string — a shape the store must reject on load. */
async function tamperSealed(): Promise<{ readonly written: boolean }> {
  const db = await requestResult<IDBDatabase>(indexedDB.open("qntx-wallet", 1));
  const tx = db.transaction("records", "readwrite");
  await requestResult(
    tx.objectStore("records").put({
      kind: "entropy",
      id: "tampered",
      header: "{}",
      sealed: "not-bytes",
    }),
  );
  await transactionDone(tx);
  return { written: true };
}

/** Opens the vault DB at a newer version — as another tab would — and reports which events fired. */
async function openNewerDb(): Promise<{
  readonly upgraded: boolean;
  readonly blocked: boolean;
  readonly success: boolean;
}> {
  return new Promise((resolve) => {
    const outcome = { upgraded: false, blocked: false, success: false };
    const request = indexedDB.open("qntx-wallet", 2);
    request.addEventListener("upgradeneeded", () => {
      outcome.upgraded = true;
    });
    request.addEventListener("blocked", () => {
      outcome.blocked = true;
    });
    request.addEventListener("success", () => {
      outcome.success = true;
      request.result.close();
      resolve(outcome);
    });
    request.addEventListener("error", () => {
      resolve(outcome);
    });
  });
}

const api = {
  stats,
  async create(): Promise<unknown> {
    return attempt(async () => {
      const created = await createWebWallet(OPTIONS);
      wallet = created;
      return created.getSnapshot();
    });
  },
  snapshot(): unknown {
    return current().getSnapshot();
  },
  async createPasskey(): Promise<unknown> {
    return attempt(async () => current().wallets.createWithPasskey({ name: "Playwright Wallet" }));
  },
  async createMnemonic(password: string): Promise<unknown> {
    return attempt(async () => {
      draft = await current().wallets.createMnemonic({
        words: 12,
        factor: { kind: "password", password },
      });
      return {
        words: new TextDecoder().decode(draft.words.read()).split(" "),
        quiz: [...draft.quiz],
      };
    });
  },
  async confirm(answers: ReadonlyArray<string>): Promise<unknown> {
    return attempt(async () => {
      if (draft === undefined) {
        throw new Error("no draft");
      }
      return draft.confirm(answers);
    });
  },
  async lock(): Promise<unknown> {
    return attempt(async () => current().vault.lock());
  },
  async reset(): Promise<unknown> {
    return attempt(async () => current().vault.reset());
  },
  async unlockPassword(password: string): Promise<unknown> {
    return attempt(async () => current().vault.unlock({ kind: "password", password }));
  },
  async unlockPasskey(): Promise<unknown> {
    return attempt(async () => current().vault.unlock({ kind: "passkey" }));
  },
  async deriveKey(walletId: string, groupIndex: number): Promise<unknown> {
    return attempt(async () => nostr(current()).deriveKey(walletId, groupIndex));
  },
  async sign(ref: NostrKeyRef, event: UnsignedEvent): Promise<unknown> {
    return attempt(async () => nostr(current()).signer(ref).signEvent(event));
  },
  tamperBackup,
  tamperSealed,
  openNewerDb,
};

Object.assign(globalThis, { qntx: api });
