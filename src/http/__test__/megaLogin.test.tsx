import { MegaHTTPApi } from "../megaApi";
import { ResponseErrorCode } from "../types";

jest.mock("../../logging", () => {
  const stub = { error: jest.fn(), debug: jest.fn(), info: jest.fn(), warn: jest.fn(), trace: jest.fn() };
  return new Proxy({}, { get: () => stub });
});

import { MegaTransition, MegaTransitionHost } from "../megaTransition";

/**
 * Exercises the REAL MegaTransition.loginMega state machine (the one complex orchestration in the v6
 * change) with a stubbed mega client + host, covering each branch: valid-session short-circuit,
 * 2FA-required, captcha-required, plain failure, lockout, hard error, success.
 */
type MegaStub = Partial<
  Pick<
    MegaHTTPApi,
    | "hasValidSession"
    | "estimateDomain"
    | "keyExchange"
    | "login"
    | "sendVerifyCode"
    | "generateCaptcha"
    | "clusterHost"
    | "exportSession"
  >
>;

function makeTransition(mega: MegaStub, opts?: { getMegaThrows?: boolean }) {
  const emitTfaRequest = jest.fn();
  const emitCaptchaRequest = jest.fn();
  const writePersistentData = jest.fn();
  const persistentData: Record<string, unknown> = {};
  const host = {
    config: { username: "a@b.c", password: "pw", country: "fr" },
    persistentData,
    get api() {
      return undefined as never;
    },
    writePersistentData,
    emitTfaRequest,
    emitCaptchaRequest,
    legacyConnect: jest.fn(async () => {}),
    onAPIConnect: jest.fn(async () => {}),
    onConnectionError: jest.fn(),
  } as unknown as MegaTransitionHost;

  const transition = new MegaTransition(host);
  // Override the lazy mega-client factory so loginMega talks to the stub.
  (transition as unknown as { getMegaApi: () => Promise<MegaHTTPApi> }).getMegaApi = jest.fn(async () => {
    if (opts?.getMegaThrows) throw new Error("init failed");
    return mega as MegaHTTPApi;
  });
  return { transition, emitTfaRequest, emitCaptchaRequest, writePersistentData, persistentData };
}

const baseMega = (over: MegaStub): MegaStub => ({
  hasValidSession: () => false,
  estimateDomain: jest.fn().mockResolvedValue({}),
  keyExchange: jest.fn().mockResolvedValue({}),
  clusterHost: () => "app-openapi-eu-pr.eufy.com",
  ...over,
});

describe("MegaTransition.loginMega", () => {
  afterEach(() => jest.clearAllMocks());

  it("short-circuits to ok when a valid session already exists", async () => {
    const mega = baseMega({ hasValidSession: () => true, login: jest.fn() });
    const { transition } = makeTransition(mega);
    await expect(transition.loginMega()).resolves.toBe("ok");
    expect(mega.login).not.toHaveBeenCalled();
  });

  it("returns tfa_required and sends the verify code on 26052", async () => {
    const sendVerifyCode = jest.fn().mockResolvedValue({ code: 0 });
    const mega = baseMega({
      login: jest.fn().mockResolvedValue({ code: ResponseErrorCode.CODE_NEED_VERIFY_CODE }),
      sendVerifyCode,
    });
    const { transition, emitTfaRequest } = makeTransition(mega);
    await expect(transition.loginMega()).resolves.toBe("tfa_required");
    expect(sendVerifyCode).toHaveBeenCalled();
    expect(emitTfaRequest).toHaveBeenCalled();
  });

  it("returns captcha_required and prompts the captcha on 100032", async () => {
    const mega = baseMega({
      login: jest.fn().mockResolvedValue({ code: ResponseErrorCode.LOGIN_NEED_CAPTCHA }),
      generateCaptcha: jest.fn().mockResolvedValue({ captcha_id: "CID", item: "img" }),
    });
    const { transition, emitCaptchaRequest } = makeTransition(mega);
    await expect(transition.loginMega()).resolves.toBe("captcha_required");
    expect(emitCaptchaRequest).toHaveBeenCalledWith("CID", "img");
  });

  it("returns failed on a non-zero/non-handled login code", async () => {
    const mega = baseMega({
      login: jest.fn().mockResolvedValue({ code: ResponseErrorCode.MULTIPLE_EMAIL_PASSWORD_ERROR }),
    });
    const { transition, writePersistentData } = makeTransition(mega);
    await expect(transition.loginMega()).resolves.toBe("failed");
    expect(writePersistentData).not.toHaveBeenCalled();
  });

  it("returns locked on a backend lockout code (no retry, no verify-code resend)", async () => {
    const sendVerifyCode = jest.fn();
    const mega = baseMega({
      login: jest.fn().mockResolvedValue({ code: ResponseErrorCode.CODE_PASSWORD_WRONG_FIVE_TIMES }),
      sendVerifyCode,
    });
    const { transition, writePersistentData } = makeTransition(mega);
    await expect(transition.loginMega()).resolves.toBe("locked");
    expect(sendVerifyCode).not.toHaveBeenCalled();
    expect(writePersistentData).not.toHaveBeenCalled();
  });

  it("returns failed (never throws) when getMegaApi throws", async () => {
    const { transition } = makeTransition({}, { getMegaThrows: true });
    await expect(transition.loginMega()).resolves.toBe("failed");
  });

  it("persists the session and returns ok on success", async () => {
    const mega = baseMega({
      login: jest.fn().mockResolvedValue({ code: 0 }),
      exportSession: jest.fn().mockReturnValue({ ab: "fr", openudid: "x", cloud_token: "t" }),
    });
    const { transition, writePersistentData, persistentData } = makeTransition(mega);
    await expect(transition.loginMega("123456")).resolves.toBe("ok");
    expect(mega.exportSession).toHaveBeenCalled();
    expect(persistentData.megaApi).toEqual({ ab: "fr", openudid: "x", cloud_token: "t" });
    expect(writePersistentData).toHaveBeenCalled();
  });
});
