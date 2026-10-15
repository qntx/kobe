import type { Worker } from "node:worker_threads";
import { MessageChannel } from "node:worker_threads";

import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { npubEncode, verifyEvent } from "@qntx/nostr";
import { WalletError } from "@qntx/wallet";
import type { Wallet } from "@qntx/wallet";
import { KernelError, createMemoryStore } from "@qntx/wallet-kernel";
import type { RecordStore } from "@qntx/wallet-kernel";
import { nostr } from "@qntx/wallet/nostr";

import { createNodeWallet, createSoftwarePasskey } from "../src/node/index.ts";
import type { NodeWalletOptions } from "../src/node/index.ts";
import { serveStore } from "../src/node/store-server.ts";
import { isBrowserWorkerInit, isNodeWorkerData } from "../src/shared.ts";
import { createStoreClient } from "../src/worker/store-client.ts";

// The worker is built by the package `test` script (bun build → dist/kernel.node.js).
const KERNEL_URL = new URL("../dist/kernel.node.js", import.meta.url);
const SEED = hexToBytes(`${"00".repeat(31)}01`);
const PASSKEY_CONFIG = {
  rpId: "qntx.test",
  rpName: "qntx",
  walletSalt: "qntx/wallet",
  vaultSalt: "qntx/vault",
};
const PASSWORD = "correct horse battery staple";

function must<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`missing ${what}`);
  }
  return value;
}

type WalletHandle = {
  readonly wallet: Wallet;
  readonly workers: Worker[];
};

async function nodeWallet(
  authenticator: ReturnType<typeof createSoftwarePasskey>,
): Promise<WalletHandle> {
  const workers: Worker[] = [];
  const options: NodeWalletOptions = {
    passkey: PASSKEY_CONFIG,
    autoLock: { platform: "web", idleMinutes: 15 },
    authenticator,
    kernelUrl: KERNEL_URL,
    onSpawn: (worker) => {
      workers.push(worker);
    },
  };
  return { wallet: await createNodeWallet(options), workers };
}

async function exited(worker: Worker): Promise<void> {
  return new Promise((resolve) => {
    worker.once("exit", () => {
      resolve();
    });
  });
}

function walletError(error: unknown): WalletError {
  if (!(error instanceof WalletError)) {
    throw error;
  }
  return error;
}

function kernelErrorCode(error: unknown): string {
  if (!(error instanceof KernelError)) {
    throw error;
  }
  return error.code;
}

describe("node host end to end", () => {
  it("creates a passkey wallet, locks by terminating the worker, unlocks and signs", async () => {
    const passkey = createSoftwarePasskey(SEED);
    const { wallet, workers } = await nodeWallet(passkey);
    const first = must(workers[0], "spawned worker");

    const created = await wallet.wallets.createWithPasskey({ name: "Node Test Wallet" });
    // Status precedes the response: the snapshot is already current when the call resolves.
    const snapshot = wallet.getSnapshot();
    expect(snapshot.vault).toBe("unlocked");
    expect(snapshot.wallets[0]?.walletId).toBe(created.walletId);
    const api = nostr(wallet);
    const key = await api.deriveKey(created.walletId, 0);
    expect(key.ref).toStrictEqual({
      kind: "derived",
      walletId: created.walletId,
      groupIndex: 0,
    });
    expect(npubEncode(key.publicKey)).toMatch(/^npub1/);

    // No settle: signing right after derive must already work (status + session are in place).
    const immediate = await api.signer(key.ref).signEvent({
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: "right after create",
      pubkey: key.publicKey,
    });
    expect(verifyEvent(immediate)).toBe(true);

    // Lock destroys the enclave: the worker exits, a fresh one spawns, snapshot survives.
    const exit = exited(first);
    await wallet.vault.lock();
    await exit; // the wait that remains is for the respawned worker's exit
    expect(workers.length).toBeGreaterThanOrEqual(2);
    const locked = wallet.getSnapshot();
    expect(locked.vault).toBe("locked");
    expect(locked.wallets[0]?.walletId).toBe(created.walletId);
    expect(locked.nostr.keys[0]?.publicKey).toBe(key.publicKey);

    // Unlock with the passkey and sign through the proxy.
    await wallet.vault.unlock({ kind: "passkey" });
    expect(wallet.getSnapshot().vault).toBe("unlocked");
    const signer = api.signer(key.ref);
    const event = await signer.signEvent({
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: "hello from the worker",
      pubkey: key.publicKey,
    });
    expect(event.pubkey).toBe(key.publicKey);
    expect(verifyEvent(event)).toBe(true);
    await wallet.destroy();
  }, 60_000);

  it("password vault: mnemonic ceremony, change password, unlock", async () => {
    const passkey = createSoftwarePasskey(hexToBytes("aa".repeat(32)));
    const { wallet, workers } = await nodeWallet(passkey);
    const draft = await wallet.wallets.createMnemonic({
      words: 12,
      factor: { kind: "password", password: PASSWORD },
    });
    const words = new TextDecoder().decode(draft.words.read()).split(" ");
    const answers = draft.quiz.map((position) => must(words[position], "quiz word"));
    const created = await draft.confirm(answers);
    expect(wallet.getSnapshot().wallets[0]?.walletId).toBe(created.walletId);

    // Change password: a new password factor replaces the old one atomically.
    await wallet.vault.addFactor(
      { kind: "password", password: "a different long password" },
      { kind: "password", password: PASSWORD },
    );
    expect(wallet.getSnapshot().factors.filter((f) => f.kind === "password")).toHaveLength(1);

    await wallet.vault.lock();
    // Wait for the respawned kernel: a call posted before the locked event lands still dies
    // on the old port ("locked") — callers retry once the fresh worker is up.
    await exited(must(workers[0], "spawned worker"));
    await expect(wallet.vault.unlock({ kind: "password", password: PASSWORD })).rejects.toSatisfy(
      (e) => walletError(e).code === "wrong-password",
    );
    await wallet.vault.unlock({
      kind: "password",
      password: "a different long password",
    });
    expect(wallet.getSnapshot().vault).toBe("unlocked");
    await wallet.destroy();
  }, 120_000);

  it("imports a NIP-06 mnemonic and an nsec, exports with re-verification", async () => {
    const passkey = createSoftwarePasskey(hexToBytes("bb".repeat(32)));
    const { wallet } = await nodeWallet(passkey);
    const created = await wallet.wallets.importMnemonic({
      mnemonic: "leader monkey parrot ring guide accident before fence cannon height naive bean",
      factor: { kind: "password", password: PASSWORD },
    });
    const derived = await nostr(wallet).deriveKey(created.walletId, 0);
    expect(derived.publicKey).toBe(
      "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
    );
    expect(npubEncode(derived.publicKey)).toBe(
      "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
    );

    // The second NIP-06 vector's key — the first vector's nsec is the derived group-0 key.
    const imported = await nostr(wallet).importKey({
      nsec: "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
    });
    expect(imported.origin).toBe("nsec");
    expect(imported.publicKey).toBe(
      "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
    );

    const exported = await wallet.wallets.exportMnemonic(created.walletId, {
      kind: "password",
      password: PASSWORD,
    });
    expect(new TextDecoder().decode(exported.read())).toBe(
      "leader monkey parrot ring guide accident before fence cannon height naive bean",
    );

    const nsec = await nostr(wallet).exportKey(
      imported.ref,
      { kind: "nsec" },
      { kind: "password", password: PASSWORD },
    );
    expect(new TextDecoder().decode(nsec.read())).toBe(
      "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
    );
    await wallet.destroy();
  }, 120_000);

  it("resolves vault.reset while unlocked and lands on uninitialized", async () => {
    const passkey = createSoftwarePasskey(hexToBytes("dd".repeat(32)));
    const { wallet, workers } = await nodeWallet(passkey);
    await wallet.wallets.createWithPasskey({ name: "Node Test Wallet" });
    expect(wallet.getSnapshot().vault).toBe("unlocked");

    // The locked event trails the reset response, so the call resolves instead of
    // dying to failPending — and the pre-response status already set the snapshot.
    await wallet.vault.reset();
    expect(wallet.getSnapshot().vault).toBe("uninitialized");
    await exited(must(workers[0], "spawned worker"));
    expect(workers.length).toBeGreaterThanOrEqual(2);
    await wallet.destroy();
  }, 60_000);

  it("restores the same wallet on a fresh host with the same passkey seed", async () => {
    const passkey = createSoftwarePasskey(SEED);
    const first = await nodeWallet(passkey);
    const created = await first.wallet.wallets.createWithPasskey({ name: "Node Test Wallet" });
    const { publicKey } = await nostr(first.wallet).deriveKey(created.walletId, 0);
    await first.wallet.destroy();

    const second = await nodeWallet(passkey);
    const restored = await second.wallet.wallets.restoreWithPasskey();
    expect(restored.walletId).toBe(created.walletId);
    const restoredKey = await nostr(second.wallet).deriveKey(restored.walletId, 0);
    expect(restoredKey.publicKey).toBe(publicKey);
    await second.wallet.destroy();
  }, 60_000);

  it("rejects the native autoLock policy on Node", async () => {
    const passkey = createSoftwarePasskey(hexToBytes("cc".repeat(32)));
    const workers: Worker[] = [];
    const attempt = createNodeWallet({
      passkey: PASSKEY_CONFIG,
      autoLock: { platform: "native", backgroundSeconds: 60 },
      authenticator: passkey,
      kernelUrl: KERNEL_URL,
      onSpawn: (worker) => {
        workers.push(worker);
      },
    });
    await expect(attempt).rejects.toSatisfy((e) => walletError(e).code === "invalid-input");
    expect(workers).toHaveLength(0);
  });
});

describe("worker init validation", () => {
  it("accepts only the three idle choices and rejects extra keys", () => {
    for (const idleMinutes of [5, 15, 60] as const) {
      expect(isBrowserWorkerInit({ t: "init", idleMinutes })).toBe(true);
    }
    expect(isBrowserWorkerInit({ t: "init", idleMinutes: 7 })).toBe(false);
    expect(isBrowserWorkerInit({ t: "init", idleMinutes: 15, maxSessionMs: 3_600_000 })).toBe(
      false,
    );
    expect(isBrowserWorkerInit({ t: "init" })).toBe(false);
    expect(isBrowserWorkerInit({ t: "boot", idleMinutes: 15 })).toBe(false);
    expect(isBrowserWorkerInit("init")).toBe(false);
  });

  it("accepts only { idleMinutes, storePort } for the Node workerData", () => {
    const port = new MessageChannel().port1;
    for (const idleMinutes of [5, 15, 60] as const) {
      expect(isNodeWorkerData({ idleMinutes, storePort: port })).toBe(true);
    }
    expect(isNodeWorkerData({ idleMinutes: 7, storePort: port })).toBe(false);
    expect(isNodeWorkerData({ idleMinutes: 15, storePort: port, maxSessionMs: 1 })).toBe(false);
    expect(isNodeWorkerData({ idleMinutes: 15 })).toBe(false);
    expect(isNodeWorkerData({ storePort: port, idleMinutes: 15, extra: 1 })).toBe(false);
    port.close();
  });
});

describe("store RPC", () => {
  /** A store client/server pair wired directly over a MessageChannel — no worker needed. */
  function storePair(store: RecordStore): {
    readonly client: RecordStore;
    readonly stop: () => void;
  } {
    const channel = new MessageChannel();
    const stop = serveStore(store, channel.port1);
    const client = createStoreClient({
      post: (message) => {
        channel.port2.postMessage(message);
      },
      listen: (handler) => {
        const listener = (message: unknown) => {
          handler(message);
        };
        channel.port2.on("message", listener);
        return () => {
          channel.port2.off("message", listener);
        };
      },
    });
    channel.port2.start();
    return {
      client,
      stop: () => {
        stop();
        channel.port2.close();
      },
    };
  }

  it("a failed commit replies with the KernelError code instead of hanging", async () => {
    const { client, stop } = storePair(createMemoryStore());
    try {
      // An expect-revision guard on an empty store cannot hold — the server replies "failed"
      // and the client rejects with the conflict code, never hangs.
      await expect(client.commit([{ op: "expect-revision", revision: 7 }])).rejects.toSatisfy(
        (e) => kernelErrorCode(e) === "conflict",
      );
      // The channel still works afterwards.
      const image = await client.load();
      expect(image.meta).toBeUndefined();
    } finally {
      stop();
    }
  });

  it("a non-kernel store failure maps to unavailable on the client", async () => {
    const failing: RecordStore = {
      load: async () => Promise.reject(new Error("disk gone")),
      commit: async () => Promise.reject(new Error("disk gone")),
      watch: () => () => undefined,
    };
    const { client, stop } = storePair(failing);
    try {
      await expect(client.load()).rejects.toSatisfy((e) => kernelErrorCode(e) === "unavailable");
      await expect(client.commit([{ op: "clear" }])).rejects.toSatisfy(
        (e) => kernelErrorCode(e) === "unavailable",
      );
    } finally {
      stop();
    }
  });
});
