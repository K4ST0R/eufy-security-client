jest.mock("../../logging", () => {
  const stub = { error: jest.fn(), debug: jest.fn(), info: jest.fn(), warn: jest.fn(), trace: jest.fn() };
  return new Proxy({}, { get: () => stub });
});

import { MegaTransition, MegaTransitionHost, MegaLoginResult } from "../megaTransition";

/**
 * Validates the v6-first connect() state machine (MegaTransition) without any network, by stubbing
 * its mega client (loginMega) and host (legacyConnect / onAPIConnect). Covers the invariants:
 *  - v6 first; legacy is best-effort and runs only after mega is settled
 *  - a backend that needs a 2FA/captcha records pendingChallenge and connect() returns WITHOUT
 *    signalling the app (no onAPIConnect)
 *  - the next code/captcha is routed to the backend that asked for it
 *  - onAPIConnect fires exactly once, at the end, only if at least one login succeeded
 *  - concurrent connect() calls are serialised
 */

interface Harness {
  transition: MegaTransition;
  onAPIConnect: jest.Mock;
  loginMega: jest.Mock;
  legacyConnect: jest.Mock;
  onConnectionError: jest.Mock;
  state: { connected: boolean };
}

function makeHarness(opts: {
  megaResults: MegaLoginResult[]; // one per loginMega call
  legacy: (t: MegaTransition) => Promise<void>; // simulate the legacy login (may set challenge / connect)
}): Harness {
  const state = { connected: false };
  const onAPIConnect = jest.fn(async () => {});
  const onConnectionError = jest.fn();

  // The real EufySecurity.legacyConnect swallows its own errors; mirror that here.
  const legacyConnect = jest.fn(async () => {
    try {
      await opts.legacy(transition);
    } catch {
      /* legacy login failed — best-effort, ignored */
    }
  });

  const host = {
    config: {},
    persistentData: {},
    get api() {
      return { isConnected: () => state.connected } as never;
    },
    writePersistentData: jest.fn(),
    emitTfaRequest: jest.fn(),
    emitCaptchaRequest: jest.fn(),
    legacyConnect,
    onAPIConnect,
    onConnectionError,
  } as unknown as MegaTransitionHost;

  const transition = new MegaTransition(host);

  // Mirror the real loginMega: a tfa/captcha result records pendingChallenge="mega" before returning.
  const loginMega = jest.fn(async () => {
    const r = opts.megaResults.shift() ?? "ok";
    if (r === "tfa_required" || r === "captcha_required") {
      (transition as unknown as { pendingChallenge?: string }).pendingChallenge = "mega";
    }
    return r;
  });
  (transition as unknown as { loginMega: jest.Mock }).loginMega = loginMega;

  return { transition, onAPIConnect, loginMega, legacyConnect, onConnectionError, state };
}

const connect = (h: Harness, opts?: { verifyCode?: string; captcha?: { captchaId: string; captchaCode: string } }) =>
  h.transition.connect(opts as never);

describe("connect() v6-first state machine", () => {
  it("nominal: mega ok + legacy ok → onAPIConnect once", async () => {
    const h = makeHarness({
      megaResults: ["ok"],
      legacy: async () => {
        h.state.connected = true;
      },
    });
    await connect(h);
    expect(h.loginMega).toHaveBeenCalledTimes(1);
    expect(h.legacyConnect).toHaveBeenCalledTimes(1);
    expect(h.onAPIConnect).toHaveBeenCalledTimes(1);
  });

  it("mega needs 2FA → returns without legacy or onAPIConnect, pendingChallenge=mega", async () => {
    const h = makeHarness({ megaResults: ["tfa_required"], legacy: async () => {} });
    await connect(h);
    expect((h.transition as any).pendingChallenge).toBe("mega");
    expect(h.legacyConnect).not.toHaveBeenCalled();
    expect(h.onAPIConnect).not.toHaveBeenCalled();
  });

  it("legacy emits a challenge → returns WITHOUT onAPIConnect (no premature connect)", async () => {
    const h = makeHarness({
      megaResults: ["ok"],
      legacy: async (t) => {
        // emulate the api "tfa request" hook firing during the legacy login
        t.recordLegacyChallenge();
      },
    });
    await connect(h);
    expect(h.onAPIConnect).not.toHaveBeenCalled();
    expect((h.transition as any).pendingChallenge).toBe("legacy");
  });

  it("routes the mega code to mega, then legacy code to legacy, onAPIConnect at the end", async () => {
    const h = makeHarness({
      megaResults: ["tfa_required", "ok"],
      legacy: async (t) => {
        if (h.legacyConnect.mock.calls.length === 1)
          t.recordLegacyChallenge(); // legacy asks on first try
        else h.state.connected = true; // legacy ok on second
      },
    });
    await connect(h); // -> pendingChallenge mega
    expect((h.transition as any).pendingChallenge).toBe("mega");

    await connect(h, { verifyCode: "MEGACODE" }); // mega ok -> legacy asks
    expect(h.loginMega).toHaveBeenLastCalledWith("MEGACODE", undefined);
    expect((h.transition as any).pendingChallenge).toBe("legacy");
    expect(h.onAPIConnect).not.toHaveBeenCalled();

    await connect(h, { verifyCode: "LEGACYCODE" }); // legacy ok -> done
    expect(h.onAPIConnect).toHaveBeenCalledTimes(1);
  });

  it("legacy captcha then 2FA in one login() → still no onAPIConnect until 2FA done", async () => {
    const h = makeHarness({
      megaResults: ["ok"],
      legacy: async (t) => {
        // captcha accepted, but server now wants a 2FA code
        t.recordLegacyChallenge();
      },
    });
    (h.transition as any).pendingChallenge = "legacy"; // we arrived here because legacy had asked the captcha
    (h.transition as any).megaLoggedIn = true; // mega already done in a previous call
    await connect(h, { captcha: { captchaId: "cid", captchaCode: "DdYE" } });
    expect(h.onAPIConnect).not.toHaveBeenCalled();
    expect((h.transition as any).pendingChallenge).toBe("legacy");
  });

  it("both logins fail → no onAPIConnect, emits connection error", async () => {
    const h = makeHarness({ megaResults: ["failed"], legacy: async () => {} });
    await connect(h);
    expect(h.onAPIConnect).not.toHaveBeenCalled();
    expect(h.onConnectionError).toHaveBeenCalledWith(expect.any(Error));
  });

  it("legacy decommissioned (mega ok, legacy throws) → onAPIConnect still fires", async () => {
    const h = makeHarness({
      megaResults: ["ok"],
      legacy: async () => {
        throw new Error("legacy gone");
      },
    });
    await connect(h);
    expect(h.onAPIConnect).toHaveBeenCalledTimes(1);
  });

  it("serialises concurrent connect() calls", async () => {
    let resolveMega: (v: MegaLoginResult) => void;
    const h = makeHarness({
      megaResults: [],
      legacy: async () => {
        h.state.connected = true;
      },
    });
    (h.loginMega as jest.Mock).mockImplementation(() => new Promise((r) => (resolveMega = r as never)));

    const p1 = connect(h);
    const p2 = connect(h); // should await the same in-flight run
    resolveMega!("ok");
    await Promise.all([p1, p2]);
    expect(h.loginMega).toHaveBeenCalledTimes(1);
    expect(h.onAPIConnect).toHaveBeenCalledTimes(1);
  });
});
