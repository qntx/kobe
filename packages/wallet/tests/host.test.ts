import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import { getPublicKey, KeysSigner } from "@qntx/nostr";
import type { UnsignedEvent } from "@qntx/nostr";

import type { MainPort } from "../src/channel.ts";
import { nostr } from "../src/nostr/index.ts";
import type { ProtocolValue } from "../src/protocol/index.ts";
import { WalletError } from "../src/types.ts";
import type { NostrKeyInfo, StatusPayload, WalletErrorCode } from "../src/types.ts";
import { connectKernel } from "../src/wallet.ts";

const SECRET_KEY = hexToBytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
const PUBLIC_KEY = getPublicKey(SECRET_KEY);
const SIGNER = new KeysSigner(SECRET_KEY);

const NOSTR_KEY: NostrKeyInfo = {
  ref: { kind: "standalone", id: PUBLIC_KEY },
  publicKey: PUBLIC_KEY,
  origin: "nsec",
  createdAt: 1,
};

const PASSKEY = {
  rpId: "qntx.test",
  rpName: "qntx",
  walletSalt: "qntx/wallet",
  vaultSalt: "qntx/vault",
};

type Request = {
  readonly id: number;
  readonly method: string;
  readonly session?: string;
  readonly params: ProtocolValue;
};

type Reply = { readonly ok: ProtocolValue } | { readonly err: { readonly code: WalletErrorCode } };

type Handler = (request: Request) => Reply | Promise<Reply>;

/**
 * A scripted kernel stand-in. Each spawned port delivers the current status on attach; requests are
 * routed through `handlers` (missing handler → err "integrity", like a confused peer would).
 */
class FakeKernel {
  status: StatusPayload;
  readonly handlers = new Map<string, Handler>();
  private active: ScriptedPort | undefined;

  constructor(status: StatusPayload) {
    this.status = status;
    this.handlers.set("status", () => ({ ok: this.status }));
  }

  attach(port: ScriptedPort): void {
    this.active = port;
    // A real kernel delivers its first status asynchronously (the worker has to boot).
    setTimeout(() => {
      port.send({ v: 1, event: "status", status: this.status });
    });
  }

  detach(port: ScriptedPort): void {
    if (this.active === port) {
      this.active = undefined;
    }
  }

  receive(port: ScriptedPort, request: Request): void {
    const handler = this.handlers.get(request.method);
    const respond = (reply: Reply): void => {
      port.send({ v: 1, id: request.id, ...reply });
    };
    if (handler === undefined) {
      respond({ err: { code: "integrity" } });
      return;
    }
    void Promise.resolve(handler(request)).then(respond);
  }

  lock(reason: "idle" | "user" | "expired"): void {
    this.status = { ...this.status, vault: "locked" };
    this.active?.send({ v: 1, event: "locked", reason });
    this.active?.send({ v: 1, event: "status", status: this.status });
  }

  pushStatus(): void {
    this.active?.send({ v: 1, event: "status", status: this.status });
  }

  /** A raw kernel → host message (e.g. the trailing locked event of an in-request lock). */
  send(message: unknown): void {
    this.active?.send(message);
  }
}

class ScriptedPort implements MainPort {
  dead = false;
  private readonly kernel: FakeKernel;
  private handler: ((message: unknown) => void) | undefined;
  private exitHandler: (() => void) | undefined;

  constructor(kernel: FakeKernel) {
    this.kernel = kernel;
  }

  post(message: ProtocolValue): void {
    if (this.dead) {
      return;
    }
    this.kernel.receive(this, message as Request);
  }

  listen(handler: (message: unknown) => void): () => void {
    this.handler = handler;
    return () => {
      this.handler = undefined;
    };
  }

  onExit(handler: () => void): () => void {
    this.exitHandler = handler;
    return () => {
      this.exitHandler = undefined;
    };
  }

  terminate(): void {
    this.dead = true;
    this.kernel.detach(this);
    this.exitHandler?.();
  }

  send(message: unknown): void {
    this.handler?.(message);
  }

  /** A crash: exits without terminate having been called. */
  crash(): void {
    this.dead = true;
    this.kernel.detach(this);
    this.exitHandler?.();
  }
}

function unlockedStatus(): StatusPayload {
  return {
    protocol: 1,
    vault: "unlocked",
    factors: [{ kind: "passkey", id: "f".repeat(32), credentialId: "Y3JlZA", createdAt: 1 }],
    wallets: [],
    nostr: { keys: [NOSTR_KEY] },
  };
}

async function connectFake(status: StatusPayload): Promise<{
  wallet: Awaited<ReturnType<typeof connectKernel>>;
  kernel: FakeKernel;
  spawned: ScriptedPort[];
}> {
  const kernel = new FakeKernel(status);
  const spawned: ScriptedPort[] = [];
  const wallet = await connectKernel({
    spawn: () => {
      const port = new ScriptedPort(kernel);
      spawned.push(port);
      kernel.attach(port);
      return port;
    },
    passkey: PASSKEY,
    ceremony: undefined,
  });
  return { wallet, kernel, spawned };
}

function walletError(error: unknown): WalletError {
  if (!(error instanceof WalletError)) {
    throw error;
  }
  return error;
}

describe("response validation", () => {
  it("rejects an invalid ok payload with integrity and breaks the wallet", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.handlers.set("dataKeys.get", () => ({ ok: "not-bytes" }));
    await expect(wallet.dataKeys.get("notes")).rejects.toSatisfy(
      (e) => walletError(e).code === "integrity",
    );
    // A kernel that answers off-schema is untrustworthy: terminal state, no respawn.
    expect(spawned).toHaveLength(1);
    expect(spawned.at(0)?.dead).toBe(true);
    await expect(wallet.dataKeys.get("notes")).rejects.toSatisfy(
      (e) => walletError(e).code === "integrity",
    );
  });

  it("rejects a forged kernel signature with integrity", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    kernel.handlers.set("nostr.signEvent", () => ({
      ok: {
        id: "0".repeat(64),
        pubkey: PUBLIC_KEY,
        sig: "0".repeat(128),
        kind: 1,
        created_at: 1,
        tags: [],
        content: "forged",
      },
    }));
    const signer = nostr(wallet).signer(NOSTR_KEY.ref);
    await expect(
      signer.signEvent({ kind: 1, created_at: 1, tags: [], content: "x", pubkey: PUBLIC_KEY }),
    ).rejects.toSatisfy((e) => walletError(e).code === "integrity");
  });

  it("rejects a valid signature over different content with integrity", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    // A compromised kernel signs honestly but swaps the content/tags — still forged.
    kernel.handlers.set("nostr.signEvent", async () => ({
      ok: await SIGNER.signEvent({
        pubkey: PUBLIC_KEY,
        kind: 1,
        created_at: 1,
        tags: [],
        content: "different",
      }),
    }));
    const signer = nostr(wallet).signer(NOSTR_KEY.ref);
    await expect(
      signer.signEvent({ kind: 1, created_at: 1, tags: [], content: "x", pubkey: PUBLIC_KEY }),
    ).rejects.toSatisfy((e) => walletError(e).code === "integrity");
  });

  it("fails pending calls on an unattributed response and breaks the wallet", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.handlers.set("dataKeys.get", async () => new Promise<Reply>(() => undefined)); // never resolves
    const snapshot = wallet.getSnapshot();
    const pending = wallet.dataKeys.get("notes");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    }); // let the request reach the kernel
    spawned.at(0)?.send({ v: 1, id: 0, ok: null }); // UNATTRIBUTED_ID — cannot be a live request
    await expect(pending).rejects.toSatisfy((e) => walletError(e).code === "integrity");
    // Poison is terminal: the port is terminated, nothing respawns, every later call fails
    // integrity, and the snapshot is untouched.
    expect(spawned).toHaveLength(1);
    expect(spawned.at(0)?.dead).toBe(true);
    await expect(wallet.dataKeys.get("notes")).rejects.toSatisfy(
      (e) => walletError(e).code === "integrity",
    );
    await expect(wallet.vault.reset()).rejects.toSatisfy(
      (e) => walletError(e).code === "integrity",
    );
    expect(wallet.getSnapshot()).toBe(snapshot);
  });
});

describe("port lifecycle", () => {
  it("fails pending requests with crashed on port exit and respawns", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.status = { ...kernel.status, vault: "locked" }; // a crashed kernel reloads locked
    kernel.handlers.set("dataKeys.get", async () => new Promise<Reply>(() => undefined)); // never resolves
    const pending = wallet.dataKeys.get("notes");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    }); // let the request reach the kernel
    spawned.at(0)?.crash();
    await expect(pending).rejects.toSatisfy((e) => walletError(e).code === "crashed");
    expect(spawned).toHaveLength(2);
    kernel.handlers.set("dataKeys.get", () => ({ err: { code: "locked" } })); // respawned kernel is locked
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(wallet.getSnapshot().vault).toBe("locked");
    expect(wallet.getSnapshot().lockReason).toBe("crashed");
    expect(spawned.at(0)?.dead).toBe(true);
  });

  it("a respawned port that dies before its first status breaks the wallet", async () => {
    const { wallet, spawned } = await connectFake(unlockedStatus());
    spawned.at(0)?.crash(); // proven port → respawn begins
    const second = spawned.at(1);
    expect(second).toBeDefined();
    second?.crash(); // dies before delivering any status — terminal
    await expect(wallet.dataKeys.get("notes")).rejects.toSatisfy(
      (e) => walletError(e).code === "integrity",
    );
    expect(spawned).toHaveLength(2);
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    }); // a stray status from the dead port must not resurrect anything
    expect(spawned).toHaveLength(2);
  });

  it("keeps the snapshot and respawns when the kernel emits a locked event", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.handlers.set("dataKeys.get", () => ({ ok: new Uint8Array(32) }));
    kernel.lock("idle");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(spawned).toHaveLength(2);
    expect(spawned.at(0)?.dead).toBe(true);
    const snapshot = wallet.getSnapshot();
    expect(snapshot.vault).toBe("locked");
    expect(snapshot.lockReason).toBe("idle");
    expect(snapshot.nostr.keys.at(0)?.publicKey).toBe(PUBLIC_KEY);

    // The fresh kernel answers session methods with "locked".
    kernel.handlers.set("dataKeys.get", () => ({ err: { code: "locked" } }));
    await expect(wallet.dataKeys.get("notes")).rejects.toSatisfy(
      (e) => walletError(e).code === "locked",
    );
  });
});

describe("connect lifecycle", () => {
  it("rejects connect with integrity on a protocol version mismatch, spawning once", async () => {
    const kernel = new FakeKernel(unlockedStatus());
    const spawned: ScriptedPort[] = [];
    const attempt = connectKernel({
      spawn: () => {
        const port = new ScriptedPort(kernel);
        spawned.push(port);
        // A kernel speaking a different protocol version: the status event fails validation.
        setTimeout(() => {
          port.send({ v: 2, event: "status", status: kernel.status });
        });
        return port;
      },
      passkey: PASSKEY,
      ceremony: undefined,
    });
    await expect(attempt).rejects.toSatisfy((e) => walletError(e).code === "integrity");
    expect(spawned).toHaveLength(1);
    expect(spawned.at(0)?.dead).toBe(true);
  });

  it("rejects connect with integrity when the port dies before its first status", async () => {
    const kernel = new FakeKernel(unlockedStatus());
    const spawned: ScriptedPort[] = [];
    const attempt = connectKernel({
      spawn: () => {
        const port = new ScriptedPort(kernel);
        spawned.push(port);
        setTimeout(() => {
          port.crash(); // e.g. the worker script blocked by CSP — no status ever arrives
        });
        return port;
      },
      passkey: PASSKEY,
      ceremony: undefined,
    });
    await expect(attempt).rejects.toSatisfy((e) => walletError(e).code === "integrity");
    expect(spawned).toHaveLength(1);
  });
});

describe("proxy signer", () => {
  it("survives lock/unlock and verifies real signatures", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    const realSign: Handler = async (request) => {
      const params = request.params as {
        publicKey: string;
        event: { kind: number; created_at: number; tags: string[][]; content: string };
      };
      const unsigned: UnsignedEvent = {
        pubkey: params.publicKey,
        kind: params.event.kind,
        created_at: params.event.created_at,
        tags: params.event.tags,
        content: params.event.content,
      };
      return { ok: await SIGNER.signEvent(unsigned) };
    };
    kernel.handlers.set("nostr.signEvent", realSign);
    kernel.handlers.set("vault.unlock", () => {
      kernel.status = { ...kernel.status, vault: "unlocked" };
      kernel.pushStatus();
      return { ok: { session: "0a".repeat(16) } };
    });

    const signer = nostr(wallet).signer(NOSTR_KEY.ref);
    await expect(signer.getPublicKey()).resolves.toBe(PUBLIC_KEY);
    const signed = await signer.signEvent({
      kind: 1,
      created_at: 100,
      tags: [],
      content: "hello",
      pubkey: PUBLIC_KEY,
    });
    expect(signed.pubkey).toBe(PUBLIC_KEY);

    kernel.lock("user");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(wallet.getSnapshot().vault).toBe("locked");

    // Locked: the kernel's error maps to WalletError locked.
    kernel.handlers.set("nostr.signEvent", () => ({ err: { code: "locked" } }));
    await expect(
      signer.signEvent({ kind: 1, created_at: 1, tags: [], content: "x", pubkey: PUBLIC_KEY }),
    ).rejects.toSatisfy((e) => walletError(e).code === "locked");

    // After unlock the same proxy object works again — resolution is per call.
    kernel.handlers.set("nostr.signEvent", realSign);
    await wallet.vault.unlock({ kind: "password", password: "long enough password" });
    expect(wallet.getSnapshot().vault).toBe("unlocked");
    const again = await signer.signEvent({
      kind: 1,
      created_at: 101,
      tags: [],
      content: "back",
      pubkey: PUBLIC_KEY,
    });
    expect(again.pubkey).toBe(PUBLIC_KEY);
  });
});

describe("message ordering", () => {
  it("resolves vault.lock while the kernel emits status → response → locked", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.handlers.set("vault.lock", () => {
      kernel.status = { ...kernel.status, vault: "locked" };
      kernel.pushStatus(); // status arrives BEFORE the response
      setTimeout(() => {
        kernel.send({ v: 1, event: "locked", reason: "user" }); // locked trails the response
      });
      return { ok: null };
    });
    await wallet.vault.lock();
    // The status event already landed: the snapshot is current when the call resolves.
    expect(wallet.getSnapshot().vault).toBe("locked");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(spawned).toHaveLength(2);
    expect(spawned.at(0)?.dead).toBe(true);
    expect(wallet.getSnapshot().lockReason).toBe("user");
  });

  it("resolves vault.reset while unlocked; the snapshot ends uninitialized", async () => {
    const { wallet, kernel, spawned } = await connectFake(unlockedStatus());
    kernel.handlers.set("vault.reset", () => {
      kernel.status = { ...kernel.status, vault: "uninitialized" };
      kernel.pushStatus();
      setTimeout(() => {
        kernel.send({ v: 1, event: "locked", reason: "user" });
      });
      return { ok: null };
    });
    await wallet.vault.reset();
    expect(wallet.getSnapshot().vault).toBe("uninitialized");
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(spawned).toHaveLength(2);
  });
});

describe("snapshot", () => {
  it("works unbound: getSnapshot and subscribe detach from the wallet object", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    // useSyncExternalStore(wallet.subscribe, wallet.getSnapshot) calls them unbound.
    const { getSnapshot, subscribe } = wallet;
    let calls = 0;
    const unsubscribe = subscribe(() => {
      calls++;
    });
    expect(getSnapshot().vault).toBe("unlocked");
    kernel.status = { ...kernel.status, vault: "locked" };
    kernel.pushStatus();
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(calls).toBe(1);
    expect(getSnapshot().vault).toBe("locked");
    unsubscribe();
  });

  it("notifies subscribers only when the snapshot actually changes", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    let calls = 0;
    wallet.subscribe(() => {
      calls++;
    });
    const first = wallet.getSnapshot();
    kernel.pushStatus(); // identical payload → no new snapshot
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(calls).toBe(0);
    expect(wallet.getSnapshot()).toBe(first);

    kernel.status = { ...kernel.status, vault: "locked" };
    kernel.pushStatus();
    await new Promise<void>((resolve) => {
      setTimeout(resolve);
    });
    expect(calls).toBe(1);
    expect(wallet.getSnapshot()).not.toBe(first);
    expect(wallet.getSnapshot().vault).toBe("locked");
  });
});

describe("nostr module factory", () => {
  it("returns the same object for the same wallet and rejects foreign objects", async () => {
    const { wallet } = await connectFake(unlockedStatus());
    const first = nostr(wallet);
    expect(nostr(wallet)).toBe(first);
    expect(() => nostr({ ...wallet })).toThrow(WalletError);
    expect(() => nostr({} as Parameters<typeof nostr>[0])).toThrow(
      expect.objectContaining({ code: "invalid-input" }) as WalletError,
    );
  });
});

describe("ExportedSecret", () => {
  it("reads exactly once and wipes", async () => {
    const { wallet, kernel } = await connectFake(unlockedStatus());
    const secret = utf8ToBytes("abandon abandon abandon");
    kernel.handlers.set("wallet.exportMnemonic", () => ({ ok: new Uint8Array(secret) }));
    const verify = { kind: "password" as const, password: "long enough password" };
    const exported = await wallet.wallets.exportMnemonic("0".repeat(16), verify);
    const bytes = exported.read();
    expect(new TextDecoder().decode(bytes)).toBe("abandon abandon abandon");
    expect(() => exported.read()).toThrow(WalletError);
    exported.wipe();
  });
});
