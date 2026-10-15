import type { Worker } from "node:worker_threads";

import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { npubEncode, verifyEvent } from "@qntx/nostr";
import { WalletError } from "@qntx/wallet";
import type { NostrKeyInfo, Wallet } from "@qntx/wallet";

import { createNodeWallet, createSoftwarePasskey } from "../src/node/index.ts";
import type { NodeWalletOptions } from "../src/node/index.ts";

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

function derivedKey(wallet: Wallet): NostrKeyInfo {
  return must(
    wallet.getSnapshot().nostrKeys.find((key) => key.ref.kind === "derived"),
    "derived nostr key",
  );
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
    expect(snapshot.wallets[0]?.walletId).toBe(created.wallet.walletId);
    const nostr = derivedKey(wallet);
    expect(nostr.ref).toStrictEqual({
      kind: "derived",
      walletId: created.wallet.walletId,
      groupIndex: 0,
    });
    expect(npubEncode(nostr.publicKey)).toMatch(/^npub1/);

    // No settle: signing right after create must already work (status + session are in place).
    const immediate = await wallet.nostr.signer(nostr.ref).signEvent({
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: "right after create",
      pubkey: nostr.publicKey,
    });
    expect(verifyEvent(immediate)).toBe(true);

    // Lock destroys the enclave: the worker exits, a fresh one spawns, snapshot survives.
    const exit = exited(first);
    await wallet.vault.lock();
    await exit; // the wait that remains is for the respawned worker's exit
    expect(workers.length).toBeGreaterThanOrEqual(2);
    const locked = wallet.getSnapshot();
    expect(locked.vault).toBe("locked");
    expect(locked.wallets[0]?.walletId).toBe(created.wallet.walletId);
    expect(locked.nostrKeys[0]?.publicKey).toBe(nostr.publicKey);

    // Unlock with the passkey and sign through the proxy.
    await wallet.vault.unlock({ kind: "passkey" });
    expect(wallet.getSnapshot().vault).toBe("unlocked");
    const signer = wallet.nostr.signer(nostr.ref);
    const event = await signer.signEvent({
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: "hello from the worker",
      pubkey: nostr.publicKey,
    });
    expect(event.pubkey).toBe(nostr.publicKey);
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
    expect(wallet.getSnapshot().wallets[0]?.walletId).toBe(created.wallet.walletId);

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
    const derived = derivedKey(wallet);
    expect(derived.publicKey).toBe(
      "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
    );
    expect(npubEncode(derived.publicKey)).toBe(
      "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
    );

    // The second NIP-06 vector's key — the first vector's nsec is the derived group-0 key.
    const imported = await wallet.nostr.importKey({
      nsec: "nsec1c9wh8xy5eqdzln7n5t0ctgxjcrdug73gp5yj0x03gntn67h83twssdfhel",
    });
    expect(imported.origin).toBe("nsec");
    expect(imported.publicKey).toBe(
      "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573",
    );

    const exported = await wallet.exports.mnemonic(created.wallet.walletId, {
      kind: "password",
      password: PASSWORD,
    });
    expect(new TextDecoder().decode(exported.read())).toBe(
      "leader monkey parrot ring guide accident before fence cannon height naive bean",
    );

    const nsec = await wallet.exports.nostrKey(
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
    const { publicKey } = derivedKey(first.wallet);
    await first.wallet.destroy();

    const second = await nodeWallet(passkey);
    const restored = await second.wallet.wallets.restoreWithPasskey();
    expect(restored.wallet.walletId).toBe(created.wallet.walletId);
    expect(restored.nostr.publicKey).toBe(publicKey);
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
