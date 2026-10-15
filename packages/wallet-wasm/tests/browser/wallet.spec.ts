/**
 * Web host end-to-end: the real kernel worker against a CDP virtual authenticator (protocol ctap2,
 * internal transport, PRF-capable). Runs against the page built and served by vite-plus from the
 * package's dist output.
 */
import { expect, test } from "@playwright/test";
import type { BrowserContext, Page } from "@playwright/test";

import { npubEncode, verifyEvent } from "@qntx/nostr";
import type { NostrKeyRef, WalletSnapshot } from "@qntx/wallet";

const PASSWORD = "correct horse battery staple";

async function virtualAuthenticator(context: BrowserContext, page: Page): Promise<void> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
    },
  });
}

async function openWalletPage(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto("/");
  const created = await page.evaluate(async () => qntx.create());
  if (!created.ok) {
    throw new Error(`createWebWallet failed: ${created.code}`);
  }
  return page;
}

async function snapshot(page: Page): Promise<WalletSnapshot> {
  return page.evaluate(() => qntx.snapshot());
}

async function walletCount(page: Page): Promise<number> {
  return page.evaluate(() => qntx.snapshot().wallets.length);
}

async function backedUp(page: Page): Promise<boolean | undefined> {
  return page.evaluate(() => qntx.snapshot().wallets[0]?.backedUp);
}

async function spawned(page: Page): Promise<number> {
  return page.evaluate(() => qntx.stats.spawned);
}

async function terminated(page: Page): Promise<number> {
  return page.evaluate(() => qntx.stats.terminated);
}

test.describe("web host", () => {
  test("passkey wallet: create, lock terminates the worker, unlock, sign", async ({
    context,
    page,
  }) => {
    await virtualAuthenticator(context, page);
    await page.goto("/");
    const connected = await page.evaluate(async () => qntx.create());
    expect(connected.ok).toBe(true);

    const created = await page.evaluate(async () => qntx.createPasskey());
    if (!created.ok) {
      throw new Error(`createWithPasskey failed: ${created.code}`);
    }
    let snap = await snapshot(page);
    expect(snap.vault).toBe("unlocked");
    expect(snap.wallets[0]?.walletId).toBe(created.value.wallet.walletId);
    expect(snap.nostrKeys[0]?.publicKey).toBe(created.value.nostr.publicKey);
    expect(npubEncode(created.value.nostr.publicKey)).toMatch(/^npub1/);

    // Lock destroys the enclave: the worker is terminated, a fresh one spawns, identities stay.
    const locked = await page.evaluate(async () => qntx.lock());
    expect(locked.ok).toBe(true);
    await expect.poll(async () => terminated(page)).toBeGreaterThanOrEqual(1);
    await expect.poll(async () => spawned(page)).toBeGreaterThanOrEqual(2);
    snap = await snapshot(page);
    expect(snap.vault).toBe("locked");
    expect(snap.wallets[0]?.walletId).toBe(created.value.wallet.walletId);

    const unlockedNow = await page.evaluate(async () => qntx.unlockPasskey());
    expect(unlockedNow.ok).toBe(true);
    const { ref, publicKey } = created.value.nostr;
    const signed = await page.evaluate(
      async (input: { keyRef: NostrKeyRef; pubkey: string }) => {
        return qntx.sign(input.keyRef, {
          pubkey: input.pubkey,
          kind: 1,
          created_at: 1_700_000_000,
          tags: [],
          content: "hello from the browser worker",
        });
      },
      { keyRef: ref, pubkey: publicKey },
    );
    if (!signed.ok) {
      throw new Error(`signEvent failed: ${signed.code}`);
    }
    expect(signed.value.pubkey).toBe(publicKey);
    expect(verifyEvent(signed.value)).toBe(true);
  });

  test("password vault: mnemonic ceremony, reload, unlock with password", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(async () => qntx.create());
    const draft = await page.evaluate(async (p) => qntx.createMnemonic(p), PASSWORD);
    if (!draft.ok) {
      throw new Error(`createMnemonic failed: ${draft.code}`);
    }
    const answers = draft.value.quiz.map((position) => {
      const word = draft.value.words[position];
      if (word === undefined) {
        throw new Error("quiz position out of range");
      }
      return word;
    });
    const confirmed = await page.evaluate(async (a) => qntx.confirm(a), answers);
    expect(confirmed.ok).toBe(true);

    // The vault lives in the worker's IndexedDB — a reload boots a fresh kernel against it.
    await page.reload();
    await page.evaluate(async () => qntx.create());
    const snap = await snapshot(page);
    expect(snap.vault).toBe("locked");
    expect(snap.lockReason).toBe("cold-start");
    expect(snap.wallets).toHaveLength(1);

    const unlockedWith = await page.evaluate(async (p) => qntx.unlockPassword(p), PASSWORD);
    expect(unlockedWith.ok).toBe(true);
    const unlocked = await page.evaluate(() => qntx.snapshot().vault);
    expect(unlocked).toBe("unlocked");
  });

  test("a second page sees the wallet without reload", async ({ context, page }) => {
    await virtualAuthenticator(context, page);
    await page.goto("/");
    await page.evaluate(async () => qntx.create());
    const pageB = await openWalletPage(context);
    expect(await walletCount(pageB)).toBe(0);

    // Page A commits; the BroadcastChannel notice makes B's worker reload and repost status.
    const made = await page.evaluate(async () => qntx.createPasskey());
    expect(made.ok).toBe(true);
    await expect.poll(async () => walletCount(pageB)).toBe(1);
    const nostrKeys = await pageB.evaluate(() => qntx.snapshot().nostrKeys.length);
    expect(nostrKeys).toBe(1);
  });

  test("a tampered record header fails unlock with integrity", async ({ context, page }) => {
    await virtualAuthenticator(context, page);
    await page.goto("/");
    await page.evaluate(async () => qntx.create());
    const made = await page.evaluate(async () => qntx.createPasskey());
    expect(made.ok).toBe(true);
    expect(await backedUp(page)).toBe(true);

    // Flip backedUp in the entropy record's header and poke the store watch channel: the kernel
    // reloads the tampered image into the live worker, so the next unlock re-authenticates it.
    const tampered = await page.evaluate(async () => qntx.tamperBackedUp());
    expect(tampered.flipped).toBe(true);
    await expect.poll(async () => backedUp(page)).toBe(false);
    const unlocked = await page.evaluate(async () => qntx.unlockPasskey());
    expect(unlocked).toEqual({ ok: false, code: "integrity" });

    // The DEK opened but a record failed authentication: the vault reports corrupted, every
    // method except status/reset answers integrity, and reset clears the vault.
    await expect.poll(async () => page.evaluate(() => qntx.snapshot().vault)).toBe("corrupted");
    const reset = await page.evaluate(async () => qntx.reset());
    expect(reset.ok).toBe(true);
    await expect.poll(async () => page.evaluate(() => qntx.snapshot().vault)).toBe("uninitialized");
  });

  test("a malformed stored row fails integrity without a respawn loop", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(async () => qntx.create());
    const draft = await page.evaluate(async (p) => qntx.createMnemonic(p), PASSWORD);
    if (!draft.ok) {
      throw new Error(`createMnemonic failed: ${draft.code}`);
    }
    const answers = draft.value.quiz.map((position) => {
      const word = draft.value.words[position];
      if (word === undefined) {
        throw new Error("quiz position out of range");
      }
      return word;
    });
    const confirmed = await page.evaluate(async (a) => qntx.confirm(a), answers);
    expect(confirmed.ok).toBe(true);

    // A row with `sealed` as a string, written around the store watch channel: the running
    // kernel keeps its committed image; the next boot loads the poisoned store.
    const tampered = await page.evaluate(async () => qntx.tamperSealed());
    expect(tampered.written).toBe(true);

    const locked = await page.evaluate(async () => qntx.lock());
    expect(locked.ok).toBe(true);
    await expect.poll(async () => terminated(page)).toBeGreaterThanOrEqual(1);
    await expect.poll(async () => spawned(page)).toBe(2);

    // The respawned worker hit the malformed row on its first load: it keeps serving and
    // reports the vault corrupted instead of crashing into a respawn loop. The status event
    // lands after the Worker constructor, so poll rather than read once.
    await expect.poll(async () => page.evaluate(() => qntx.snapshot().vault)).toBe("corrupted");
    const unlocked = await page.evaluate(async (p) => qntx.unlockPassword(p), PASSWORD);
    expect(unlocked).toEqual({ ok: false, code: "integrity" });

    // No respawn loop: the worker count stays put after the integrity failure.
    await page.waitForTimeout(500);
    expect(await spawned(page)).toBe(2);
    expect(await terminated(page)).toBe(1);

    // vault.reset is the recovery path: the corrupted vault clears to uninitialized.
    const reset = await page.evaluate(async () => qntx.reset());
    expect(reset.ok).toBe(true);
    await expect.poll(async () => page.evaluate(() => qntx.snapshot().vault)).toBe("uninitialized");
    expect(await spawned(page)).toBe(2);
  });

  test("a failed passkey ceremony surfaces as cancelled", async ({ context, page }) => {
    // isUserVerified: false — the authenticator cannot satisfy userVerification:"required",
    // so Chromium rejects the create with NotAllowedError, the same DOMException a real
    // user-cancel produces; the ceremony maps it to "cancelled".
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: false,
        hasPrf: true,
      },
    });
    await page.goto("/");
    await page.evaluate(async () => qntx.create());

    const result = await page.evaluate(async () => qntx.createPasskey());
    expect(result).toEqual({ ok: false, code: "cancelled" });
  });
});
