import { HTTPApi } from "./api";
import { MegaHTTPApi, megaLoginHash } from "./megaApi";
import { rootHTTPLogger, rootMainLogger } from "../logging";
import type { HTTPApiRequest, HTTPApiPersistentData, LoginOptions } from "./interfaces";
import type { ApiResponse } from "./models";
import type { EufySecurityConfig, EufySecurityPersistentData } from "../interfaces";
import { ResponseErrorCode } from "./types";
import { InvalidCountryCodeError, ensureError } from "../error";
import { getError } from "../utils";
import { isValid as isValidCountry } from "i18n-iso-countries";

/**
 * Everything specific to the transitional v6 "eufy_mega" backend lives in this single file so it can
 * be removed in one block once the legacy plaintext API is fully decommissioned and a native v6 data
 * layer replaces it. It holds two pieces:
 *
 *  - {@link EufyMegaTransport}: a thin {@link HTTPApi} subclass that routes mapped endpoints through
 *    the signed/encrypted v6 backend and falls back to the inherited legacy behaviour otherwise.
 *  - {@link MegaTransition}: the connect coordinator — v6-first login, legacy as best-effort
 *    afterwards, the app-ready signal fired exactly once at the end. It owns all the v6 state
 *    (mega client, pending challenge, serialisation) and talks to {@link EufySecurity} only through
 *    the narrow {@link MegaTransitionHost} surface, so neither file leaks the other's internals.
 *
 * Nothing here modifies {@link MegaHTTPApi}: this layer only consumes its public API.
 */

/** A legacy endpoint path (no query) -> its v6 cluster service + path. */
interface MegaRoute {
  service: string;
  path: string;
}

const ENDPOINT_MAP: Record<string, MegaRoute> = {
  "v2/passport/profile": { service: "passport", path: "/passport/get_user_param" },
  "v1/app/trust_device/list": { service: "passport", path: "/passport/list_trust_device" },
};

/**
 * Transitional v6 transport layered on top of {@link HTTPApi}.
 *
 * A migrated account speaks only the signed/encrypted mega transport, even on the historical
 * `*.eufylife.com` hosts; the legacy plaintext endpoints return 401. Instead of rewriting every
 * HTTPApi method, this subclass overrides the single `request()` entry point: a mapped endpoint is
 * routed through the delegate {@link MegaHTTPApi} (signed + encrypted, response decrypted), while
 * everything unmapped falls back to the inherited legacy behaviour. The map grows one entry at a
 * time as each v6 endpoint is confirmed.
 */
export class EufyMegaTransport extends HTTPApi {
  private readonly mega: MegaHTTPApi;

  protected constructor(
    apiBase: string,
    country: string,
    username: string,
    password: string,
    mega: MegaHTTPApi,
    persistentData?: HTTPApiPersistentData
  ) {
    super(apiBase, country, username, password, persistentData);
    this.mega = mega;
  }

  /** Mirror of {@link HTTPApi.initialize}, plus the shared mega client used to route v6 endpoints. */
  static async initializeWithMega(
    country: string,
    username: string,
    password: string,
    persistentData: HTTPApiPersistentData | undefined,
    mega: MegaHTTPApi
  ): Promise<EufyMegaTransport> {
    if (isValidCountry(country) && country.length === 2) {
      const apiBase = await HTTPApi.getApiBaseFromCloud(country);
      const api = new EufyMegaTransport(apiBase, country, username, password, mega, persistentData);
      await api.loadLibraries();
      return api;
    }
    throw new InvalidCountryCodeError("Invalid ISO 3166-1 Alpha-2 country code", { context: { countryCode: country } });
  }

  private static routeKey(endpoint: string | URL): string {
    const raw = typeof endpoint === "string" ? endpoint : endpoint.toString();
    return raw.split("?")[0].replace(/\/$/, "");
  }

  public override async request(request: HTTPApiRequest, withoutUrlPrefix = false): Promise<ApiResponse> {
    const route = ENDPOINT_MAP[EufyMegaTransport.routeKey(request.endpoint)];
    if (!route) {
      return super.request(request, withoutUrlPrefix);
    }
    rootHTTPLogger.debug("MegaTransport: routing via v6", { endpoint: request.endpoint, route });
    try {
      const decrypted = await this.mega.callDecrypted(route.service, route.path, request.data ?? {});
      // Re-wrap into the `{code,msg,data}` envelope the inherited HTTPApi methods expect.
      return { status: 200, statusText: "", headers: {}, data: { code: 0, msg: "success!", data: decrypted } };
    } catch (err) {
      rootHTTPLogger.warn("MegaTransport: v6 call failed", {
        endpoint: request.endpoint,
        error: (err as Error).message,
      });
      return {
        status: 500,
        statusText: (err as Error).message,
        headers: {},
        data: { code: -1, msg: (err as Error).message },
      };
    }
  }
}

/** The result of one v6 login attempt. */
export type MegaLoginResult = "ok" | "tfa_required" | "captcha_required" | "locked" | "failed";

/** Which backend a submitted 2FA code / captcha must be routed to. */
export type ChallengeSource = "mega" | "legacy";

/**
 * The narrow surface {@link MegaTransition} needs from {@link EufySecurity}. It is satisfied with a
 * small closure object (not `this`) so neither side has to expose private members nor import the
 * other — keeping the transition layer self-contained and removable.
 */
export interface MegaTransitionHost {
  readonly config: EufySecurityConfig;
  readonly persistentData: EufySecurityPersistentData;
  /** The live transport (legacy + mega), set once by {@link MegaTransition.createTransport}. */
  readonly api: HTTPApi;
  writePersistentData(): void;
  /** Re-emit the 2FA prompt to the consumer (ws / plugin). */
  emitTfaRequest(): void;
  /** Re-emit the captcha prompt to the consumer (ws / plugin). */
  emitCaptchaRequest(id: string, captcha: string): void;
  /** The original upstream `connect()` (login + trust device), unchanged. */
  legacyConnect(options?: LoginOptions): Promise<void>;
  /** Signal the app as connected (refresh + push + mqtt). Fired once at the end of the sequence. */
  onAPIConnect(): Promise<void>;
  onConnectionError(error: Error): void;
}

/**
 * Coordinates the v6-first login sequence. The v6 "eufy_mega" backend is the primary login (it
 * carries push and is where the account is heading); the legacy login runs afterwards as
 * best-effort and never blocks. Each backend has its OWN 2FA email + captcha; whichever asks
 * records itself in {@link pendingChallenge} so the code/captcha from the next connect() is routed
 * to the backend that asked for it. The app-ready signal fires ONCE, at the very end, and only if a
 * login succeeded.
 */
export class MegaTransition {
  private readonly host: MegaTransitionHost;
  private megaApi?: MegaHTTPApi;
  /**
   * Which backend a submitted 2FA code / captcha must be routed to. Set when WE emit the challenge,
   * so the next connect({verifyCode|captcha}) goes to the backend that asked for it — no guessing.
   * `undefined` = no challenge outstanding (start a fresh sequence).
   */
  private pendingChallenge?: ChallengeSource;
  /** Whether the v6 login succeeded this sequence (gates signalling the app as connected). */
  private megaLoggedIn = false;
  /** Serialises connect(): concurrent calls await the in-flight one instead of racing the sequence. */
  private connectInProgress?: Promise<void>;

  constructor(host: MegaTransitionHost) {
    this.host = host;
  }

  /** Record that the LEGACY login asked for a code/captcha (called from the host's api-event hooks). */
  public recordLegacyChallenge(): void {
    this.pendingChallenge = "legacy";
  }

  /** Build the live transport: a shared mega client wrapped by {@link EufyMegaTransport}. */
  public async createTransport(persistentHttpApi: HTTPApiPersistentData | undefined): Promise<HTTPApi> {
    const mega = await this.getMegaApi();
    return EufyMegaTransport.initializeWithMega(
      this.host.config.country!,
      this.host.config.username!,
      this.host.config.password!,
      persistentHttpApi,
      mega
    );
  }

  /**
   * Lazily create (and restore) the v6 mega client. The persisted session (token ~30 days) is
   * reused so normal startups need no extra login/2FA; it is dropped if the credentials changed.
   */
  public async getMegaApi(): Promise<MegaHTTPApi> {
    if (!this.megaApi) {
      this.megaApi = new MegaHTTPApi({
        ab: this.host.config.country ?? "US",
        osType: "android",
        phoneModel: this.host.config.trustedDeviceName,
        openudid: this.host.persistentData.openudid || undefined,
      });
      await this.megaApi.init();
      const saved = this.host.persistentData.megaApi;
      if (saved) {
        const currentHash = megaLoginHash(
          this.host.config.username,
          this.host.config.password,
          this.host.persistentData.openudid
        );
        if (saved.login_hash && saved.login_hash !== currentHash) {
          rootMainLogger.debug("v6: credentials changed since last login, ignoring stored mega session");
        } else {
          this.megaApi.restoreSession(saved);
        }
      }
    }
    return this.megaApi;
  }

  /**
   * Register the FCM token on the v6 backend, best-effort. No-ops with a log when there is no valid
   * v6 session yet (not-yet-migrated account); a v6 failure is swallowed so legacy push is unaffected.
   */
  public async registerMegaPushToken(token: string): Promise<boolean> {
    try {
      const mega = await this.getMegaApi();
      if (!mega.hasValidSession()) {
        rootMainLogger.debug("v6 push: no valid mega session yet, skipping register (legacy still active)");
        return false;
      }
      const result = await mega.registerPushToken(token);
      if (result.code === 0) {
        rootMainLogger.info("v6 push: FCM token registered on the eufy_mega backend");
        return true;
      }
      rootMainLogger.warn("v6 push: register_push_token returned a non-zero code", {
        code: result.code,
        msg: result.msg,
      });
      return false;
    } catch (err) {
      rootMainLogger.warn("v6 push: register failed (legacy push unaffected)", { error: getError(ensureError(err)) });
      return false;
    }
  }

  /**
   * Authenticate against the v6 backend.
   *  1. first call -> on `26052` triggers the email code and returns "tfa_required"; on a captcha
   *     challenge it emits "captcha request" and returns "captcha_required".
   *  2. with a code/captcha -> completes login; the session is persisted (token ~30 days) so later
   *     startups reuse it with no relogin/2FA.
   *
   * Backend-enforced lockout (too many incorrect / max login limit) is surfaced as "locked" so the
   * caller stops retrying instead of deepening the lockout.
   */
  public async loginMega(
    verifyCode?: string,
    captcha?: { captchaId: string; answer: string }
  ): Promise<MegaLoginResult> {
    try {
      const mega = await this.getMegaApi();
      if (mega.hasValidSession() && !verifyCode && !captcha) return "ok";

      await mega.estimateDomain();
      await mega.keyExchange(mega.clusterHost("openapi"));
      const result = await mega.login(this.host.config.username!, this.host.config.password!, verifyCode, captcha);

      if (result.code === ResponseErrorCode.CODE_NEED_VERIFY_CODE) {
        await mega.sendVerifyCode();
        this.pendingChallenge = "mega";
        this.host.emitTfaRequest();
        rootMainLogger.info("v6 login: email 2FA required — call loginMega(code) with the received code");
        return "tfa_required";
      }
      if (
        result.code === ResponseErrorCode.LOGIN_NEED_CAPTCHA ||
        result.code === ResponseErrorCode.LOGIN_CAPTCHA_ERROR
      ) {
        const c = await mega.generateCaptcha();
        this.pendingChallenge = "mega";
        this.host.emitCaptchaRequest(c.captcha_id, c.item);
        rootMainLogger.info("v6 login: captcha required — call loginMega(undefined, {captchaId, answer})");
        return "captcha_required";
      }
      if (
        result.code === ResponseErrorCode.CODE_PASSWORD_TOO_MANY_INCORRECT ||
        result.code === ResponseErrorCode.CODE_PASSWORD_WRONG_FIVE_TIMES ||
        result.code === ResponseErrorCode.CODE_MAX_LOGIN_LIMIT
      ) {
        rootMainLogger.warn("v6 login temporarily locked by the backend — stop retrying", {
          code: result.code,
          msg: result.msg,
        });
        return "locked";
      }
      if (result.code !== 0) {
        rootMainLogger.warn("v6 login failed", { code: result.code, msg: result.msg });
        return "failed";
      }
      this.host.persistentData.megaApi = mega.exportSession(
        megaLoginHash(this.host.config.username, this.host.config.password, this.host.persistentData.openudid)
      );
      this.host.writePersistentData();
      rootMainLogger.info("v6 login: success, mega session persisted");
      return "ok";
    } catch (err) {
      rootMainLogger.error("v6 login error", { error: getError(ensureError(err)) });
      return "failed";
    }
  }

  /** Serialised connect(): concurrent callers await the in-flight run instead of racing it. */
  public connect(options?: LoginOptions): Promise<void> {
    if (this.connectInProgress) return this.connectInProgress;
    this.connectInProgress = this.runConnect(options).finally(() => {
      this.connectInProgress = undefined;
    });
    return this.connectInProgress;
  }

  private async runConnect(options?: LoginOptions): Promise<void> {
    const megaCaptcha = options?.captcha
      ? { captchaId: options.captcha.captchaId, answer: options.captcha.captchaCode }
      : undefined;

    // PHASE 1 — v6 first. Run it unless a challenge is currently outstanding for the LEGACY side.
    if (this.pendingChallenge !== "legacy") {
      const megaResult = await this.loginMega(options?.verifyCode, megaCaptcha);
      if (megaResult === "tfa_required" || megaResult === "captcha_required") {
        // loginMega already recorded pendingChallenge="mega" and prompted the consumer.
        return;
      }
      this.megaLoggedIn = megaResult === "ok";
      this.pendingChallenge = undefined;
    }

    // PHASE 2 — legacy afterwards, best-effort. A code/captcha just used by mega is not valid here;
    // the legacy login emits its OWN tfa/captcha event (which records pendingChallenge="legacy" via
    // the host) and we wait for the next connect(). If legacy has been decommissioned, its login
    // simply fails and we carry on with v6 only.
    if (!this.host.api.isConnected()) {
      const legacyOptions =
        this.pendingChallenge === "legacy"
          ? options
          : ({ ...options, verifyCode: undefined, captcha: undefined } as LoginOptions);
      this.pendingChallenge = undefined;
      await this.host.legacyConnect(legacyOptions);
      // legacyConnect may have recorded pendingChallenge="legacy" via the host's api-event hooks.
      if (this.pendingChallenge === "legacy" && !this.host.api.isConnected()) return;
    }

    // PHASE 3 — both backends settled. Signal the app ONCE, only if a login actually succeeded.
    if (this.megaLoggedIn || this.host.api.isConnected()) {
      await this.host.onAPIConnect();
    } else {
      rootMainLogger.warn("connect: neither v6 nor legacy login succeeded — not signalling connected");
      this.host.onConnectionError(new Error("Login failed on both backends"));
    }
  }
}
