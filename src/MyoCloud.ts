import {
  BossObject,
  CachedStoredValue,
  CompletablePromise,
  ParsecSessionStorage,
  PConnection,
  RemoteException,
  RootConnection,
  Session
} from "uparsecjs";
import { KeyAddress, PrivateKey, SignedRecord } from "unicrypto";
import { Credentials } from "./Credentials";
import { ExpiringValue } from "./ExpiringValue";
import { AnnotatedKey, hashDigest64Compact } from "./AnnotatedKey";
import { MyoElement } from "./MyoElement";
import { Registry } from "./Registry";
import { CloudElement } from "./CloudData";
import { CloudObject } from "./CloudObject";
import { AnnotatedKeyring } from "./AnnotatedKeyring";
import { Inbox, InboxDefinitionRecord } from "./Inbox";
import { Config } from "./Config";
import { Emitter, EmitterEventListener, EmitterHandle } from "uparsecjs/dist/Emitter";

const LOCALSERVICE = "http://localhost:8094"
// const LOCALSERVICE = "https://myonly.cloud";
const CLOUDSERVICE = "https://myonly.cloud";

const serviceKeyAddress =
  new KeyAddress("Jzsx17iRe72ZLDnUZ9Hw8TUc1Q7qjinupJ1sG19uefcQk6QxmGgvXsANuGbBZtZRrG8KSm7f").bytes;

export type MyoEventType = "connected" | "disconnected" | "loggedIn" | "loggedOut";

export interface MyoEvent {
  type: MyoEventType;
  cloud: MyoCloud;
}

export type RegistrationResult = "OK" | "login_in_use" | "error";

export class MyoCloud implements PConnection {

  static Exception = class extends Error {
  };
  static NotFound = class extends MyoCloud.Exception {
  };
  static IllegalState = class extends MyoCloud.Exception {
  };
  static NotLoggedIn = class extends MyoCloud.IllegalState {
  };

  static InvalidPassword = class extends MyoCloud.Exception {
  };

  static LoginNotAvailable = class extends MyoCloud.Exception {
  };


  private readonly rootConnection: RootConnection;
  private readonly session: Session;
  private readonly emitter = new Emitter<MyoEvent>();
  private lastEvent?: MyoEvent;

  private readonly lastLogin: CachedStoredValue;
  readonly #expiringLoginKey = new ExpiringValue<PrivateKey>();
  private connectedPromise = new CompletablePromise<void>();

  // exact login state: undefined - not known (not yet checked), true - logged in now, false - logged aout at all.
  // it meanss, when loastLogin exists and loginState is undefined, the login might be restored. When it is false,
  // though, it means that cloud has disconnected the session an we need to re-login.
  private loginState?: boolean;

  #registry?: Registry;
  #storageKey?: AnnotatedKey;

  /**
   * Create connection to the myonly.cloud service.
   *
   * __Important note about `testMode` sessions__. Anu login registered from test mode is subject to eventual
   * cleanup by the service, we guarantee only few minutes, and it could be deleted by any other process by login
   * only, not requiring even the password, see [clearTestLogin] for details. So __do not use `testMode` excpet
   * for reqgression tests!__
   *
   * @param store where to store sensitive connection data. It is recommended to keep it in some safe or encrypted
   *              storage.
   * @param params `testMode`
   */
  constructor(private store: ParsecSessionStorage, params: { serviceAddress?: string; testMode?: boolean }) {
    let root;
    if (params.serviceAddress)
      root = params.serviceAddress;
    else {
      if (window?.location) {
        root = (window.location.hostname == 'localhost') ? LOCALSERVICE : CLOUDSERVICE;
      } else root = CLOUDSERVICE;
    }
    this.lastLogin = new CachedStoredValue(store, "lastLogin");
    this.rootConnection = new RootConnection(root);
    const kap = (_refresh: boolean) => {
      const address = params.testMode ?
        [new KeyAddress("Jmw1hQVroBHhk3Lss3Et8CTSRg3mY9j8R494ZRUvXYcvMhP5XLiV16fhh4KgRgpWZ1t7MkAv").bytes]
        : [serviceKeyAddress];
      return Promise.resolve(address);
    };
    Session.debugLogger = (...str) => { console.log("SESS::", ...str); }
    this.session = new Session(
      store,
      this.rootConnection,
      kap,
      params.testMode,
      params.testMode ? 2048 : 4096);
    this.tryRestoreSession();
  }

  traceCalls = true;

  async call(method: string, params: BossObject = {}): Promise<BossObject> {
    // TODO: catch and process connection errors
    if (this.traceCalls) console.log(`>>> ${method}`, params);
    if (this.traceCalls) console.log("||| ",this.session);
    const result = await this.session.call(method, params);
    if (this.traceCalls) console.log("<<< ", result);
    return result;
  }

  /**
   * Smart add listener. The listener receives last connection event if any. E.g. if the service is in logged in
   * state by the time of call, it will immediately receive [[MyoEvent]] with type 'loggedIn', etc. This makes
   * it safe to call at any moment in future.
   *
   * __important__. If some listener will be added several times, it will be called several times. Be sure to remove
   * unneded listeners using returned label. Invocation order is not guaranteed.
   *
   * @param lr listener to add.
   * @return listener label used to remove it
   */
  addListener(lr: EmitterEventListener<MyoEvent>): EmitterHandle {
    if (this.lastEvent) lr(this.lastEvent);
    return this.emitter.addListener(lr);
  }

  /**
   * Remove listener by its label. Will do nothing if there is no listener with such label,
   * @param listenerLabel listener label to remove.
   */
  removeListener(listenerLabel: string): void {
    this.emitter.removeListener(listenerLabel);
  }

  get connected(): CompletablePromise<void> {
    return this.connectedPromise;
  }

  /**
   * Logged in state could be: true if it is logged in now, false if user is logged out, and undefined if the
   * state is not yet known.
   */
  get isLoggedIn(): boolean | undefined {
    return this.loginState;
  }

  get hasSavedLogin(): boolean {
    return this.lastLogin.value !== null
  }

  get hasLoginKey(): boolean {
    return this.#expiringLoginKey.value != undefined;
  }

  /**
   * Create login-key based signed record promising the key is still available. If key is not available,
   * caller should restore it by providing the password to [[restoreLoginKey]]. After it returns, client
   * have at least 10 minutes to perform login-requiring operations.
   *
   * @param payload to include
   * @param nonce to use. If not set, uses parsec's standard, TSK as nonce. It is save and fast.
   * @return packed signed record or undefined if the key is not known at the moment.
   */
  async loginSignedRecord(payload: BossObject, nonce?: Uint8Array): Promise<Uint8Array | undefined> {
    const key = this.#expiringLoginKey.value;
    if (key)
      return SignedRecord.packWithKey(key, payload, nonce ?? this.session.currentTSK ?? undefined);
    else
      return undefined;
  }

  /**
   * Try to login using specified credentials. Successful login also fires [[MyoEvent]] with `type:loggedIn`.
   * If the service is in the logged in state, it must be explicitly logged out first.
   *
   * @param login to use
   * @param password to use
   * @return resolve to success if logged in
   * @throws IllegalState
   * @throws InvalidPassword
   */
  async login(login: string, password: string) {
    this.lastLogin.value = null;
    if (this.isLoggedIn) throw new MyoCloud.IllegalState("already logged in, do logout first");
    await this.restoreLoginKey(password, login);
    const loginKey = this.#expiringLoginKey.value;
    if (!loginKey)
      throw Error("internal problem: login key not set after restoring");

    await this.call("signIn", {
      keyLongAddress: loginKey.publicKey.longAddress.asString,
      signedRecord: await SignedRecord.packWithKey(loginKey, {}, this.session.currentTSK!)
    });

    // if we've get there with no exception, we are logged in.
    // now we should restore registry and happily proceed
    console.log("loggged in, preparing registry");
    // TODO: registry needs storage key
    if (!this.#storageKey) throw new Error("storage key is not set, internal error");
    this.#registry = new Registry(this, this.#storageKey);
    await this.#registry.ready;
    console.log("registry is ready");
  }

  async logout(): Promise<void> {
    if( this.isLoggedIn ) {
      await this.call("signOut");
    }
  }

  private static async newPrivateKey(): Promise<PrivateKey> {
    return PrivateKey.generate({ strength: Config.testMode ? 2048 : 8192 });
  }

  private lastPrivateKey: Promise<PrivateKey> = MyoCloud.newPrivateKey();

  /**
   * Get currently (being) generated new private key of default strength and start generating new one,
   * so we always have a private key at hand
   */
  async nextPrivateKey(): Promise<PrivateKey> {
    const k = this.lastPrivateKey;
    MyoCloud.newPrivateKey();
    return k;
  }


  /**
   * Create new cloud registration. Note that it does not automatically log in to it.
   *
   * @param login
   * @param password
   * @param loginKey specify new private key to use with a login, or null to let library to generate new one.
   *
   * @return result, namely 'OK', 'login_in_use' or 'error' if some other error has occured (e.g. network error).
   *
   * @throws MyoCloud.IllegalState if it is already logged in (log out first)
   */
  async register(login: string, password: string, loginKey?: PrivateKey): Promise<RegistrationResult> {

    await this.connected;
    if (this.isLoggedIn)
      throw new MyoCloud.IllegalState("logged in: log out to register")

    if (!loginKey)
      loginKey = await this.nextPrivateKey()

    const packedLoginKey = await Credentials.encryptLoginKey(loginKey, password);
    const key2 = await Credentials.decryptCloudKeys(password, packedLoginKey);
    if (key2.loginKey.publicKey.longAddress.base58 != loginKey.publicKey.longAddress.base58)
      throw new Error("loginKey pack double check failed");

    const nonce = this.session.currentTSK;
    if (!nonce)
      throw new Error("Session not established: no TSK");

    try {
      await this.call("signUp", {
        signedRecord: await SignedRecord.packWithKey(
          loginKey,
          { loginHash: await Credentials.deriveLoginHash(login), encryptedKey: packedLoginKey },
          nonce)
      });
      return "OK";
    }
    catch(x) {
      if( x instanceof RemoteException && x.code == "name_not_available" )
        return "login_in_use";
    }
    return "error";
  }

  /**
   * For testing only. Deletes _test login_. Test logins are all logins created from the
   * sessions opened in _test mode_, see [MyoCloud] constructor `test_mode` parameter. Note that
   * any login registered from _test_mode session_ could be deleted by anyone, so only use it for testing.
   * @param login
   */
  async clearTestLogin(login: string): Promise<void> {
    await this.call("clearTestLogin", { loginHash: await Credentials.deriveLoginHash(login)});
  }

  get mainRing(): AnnotatedKeyring {
    if (!this.#registry) throw new MyoCloud.NotLoggedIn();
    return this.#registry.mainKeyring;
  }

  /**
   * Get and decrypt login key. Could be used by client software to get the key when it is expired,
   * in which case _login parametere should be omitted_.
   *
   * Please do not specify login other than used by system or it will cause exception. When implementing
   * login protocol, be sure to drop saved login first.
   *
   * @param password to use to decrypt the login key.
   * @param login for internal use in login procedure. Login to request the key from.
   * @throws IllegalState if it is not logged in or login is pecified but is wrong. Log out or log in.
   * @throws InvalidPassword
   */
  private async restoreLoginKey(password: string, login?: string): Promise<void> {
    const useLogin = login ?? this.lastLogin.value;

    if (!useLogin)
      throw new MyoCloud.IllegalState("can't restore login key: no saved login. please login first.")

    if (this.lastLogin?.value && this.lastLogin.value != useLogin)
      throw new MyoCloud.Exception("Forbidden: this method only restores own login key");

    const result = await this.call("requestSignInKey", {
      loginHash: await Credentials.deriveLoginHash(useLogin)
    });

    let cloudKeys;
    try {
      // TODO: extracto also storage key?
      cloudKeys = await Credentials.decryptCloudKeys(password, result.encryptedKey as Uint8Array)
    } catch (e) {
      // console.error("decrypt cloud key:", e);
      throw new MyoCloud.InvalidPassword("failed to decrypt login key");
    }

    // console.log("login key decrypted: ",cloudKeys.loginKey);
    this.lastLogin.value = useLogin;
    this.#expiringLoginKey.reset(cloudKeys.loginKey, 5 * 60 * 60);
    this.#storageKey = cloudKeys.storageKey;
  }

  async elementByUniqueTag(uniqueTag: string): Promise<MyoElement | undefined> {
    const result = await this.call("getByUniqueTag", { uniqueTag });
    return result.element ? new MyoElement(this, result.element as BossObject) : undefined;
  }

  async elementByUniqueTagOrTrow(uniqueTag: string): Promise<MyoElement> {
    const element = await this.elementByUniqueTag(uniqueTag);
    if (!element)
      throw new MyoCloud.NotFound("not found utag: " + uniqueTag);
    return element;
  }

  async* inboxes(): AsyncGenerator<Inbox, void, unknown> {
    const r = await this.call("Inboxes.all") as unknown as { inboxes: InboxDefinitionRecord[] };
    for (const x of r.inboxes) {
      yield await new Inbox(this, x).ready
    }
  }

  static async simpleScramble(source: string): Promise<string> {
    return await hashDigest64Compact("SHA3_256", `myonly.cloud/simple_prefix/${source}`);
  }

  async scramble(name: string): Promise<string> {
    if (!this.#registry) throw new MyoCloud.NotLoggedIn();
    return this.#registry.scramble(name);
  }

  async objectByUniqueTag<T>(utag: string, creator?: (element: CloudElement) => Promise<CloudObject<T>>)
    : Promise<CloudObject<T> | undefined> {
    const element = await this.elementByUniqueTagOrTrow(utag);
    return !creator ? new CloudObject<T>().loadFrom(element, this) : creator(element);
  }

  // ---------------------- private implementation ---------------------

  fireEvent(type: MyoEventType) {
    this.emitter.fire({ type, cloud: this });
  }

  private async tryRestoreSession() {
    try {
      const result = await this.session.call("check");
      console.log("connected:", result);
      this.fireEvent("connected");
      // TODO: interpret the result, restore login state
      this.loginState = false;
      this.connectedPromise.resolve();
    } catch (e) {
      if (e instanceof RemoteException && e.code == 'parsec_not_signed_in') {
        this.setLoggedOut();
        this.connectedPromise.resolve();
      } else
        this.connectedPromise.reject(e);
    }
  }

  private setLoggedOut() {
    this.lastLogin.value = null;
    this.loginState = false;
    this.#expiringLoginKey.clear();
    if (this.loginState) {
      this.fireEvent("loggedOut");
      this.loginState = false;
    }
  }

}
