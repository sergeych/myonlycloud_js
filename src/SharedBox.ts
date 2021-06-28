import { Boss, SymmetricKey } from "unicrypto";
import {
  AnnotatedKey,
  annotationLabel,
  deserializeKeyAnnotation,
  KeyAnnotation,
  serializeKeyAnnotation
} from "./AnnotatedKey";
import { BossObject, BossPrimitive, equalArrays } from "uparsecjs";
import { AnnotatedKeyring } from "./AnnotatedKeyring";
import { MapSerializer, Serializable } from "./MapSerializer";

/**
 * Shared box allow encrypt its content with any number of keys so any of them allow to access its content.
 * It is possible to add more keys to existing SharedBox if it is new or unlocked.
 */
@Serializable
export class SharedBox {

  /**
   * It thrown when it is not possible to unlock the box with a given keyring
   */
  static Exception = class extends Error {}

  private packedAccessors = new Map<string,Uint8Array>();

  private constructor(
    private readonly accessors: Array<{annotation: KeyAnnotation;encryptedKey: Uint8Array}>,
    private encryptedPayload?: Uint8Array
  ) {
    for( const {annotation,encryptedKey} of accessors) {
      this.packedAccessors.set(annotationLabel(annotation), encryptedKey);
    }
  }

  #mainKey?: SymmetricKey;

  private get accessKey(): SymmetricKey {
    if( !this.#mainKey ) throw new Error("SafeBox is not unlocked/initialized");
    return this.#mainKey;
  }

  private initializeAsNew(): SharedBox {
    if( this.#mainKey || this.packedAccessors.size > 0 )
      throw new Error("SharedBox is already initialized");
    this.#mainKey = new SymmetricKey();
    return this;
  }

  async addKeys(...keys: AnnotatedKey[]): Promise<SharedBox> {
    if( !this.#mainKey )
      throw new Error("SharedBox is not initialized");
    for( const key of keys) {
      const ek = await key.etaEncrypt(this.#mainKey.pack());
      this.packedAccessors.set(key.annotationLabel, ek);
      this.accessors.push({annotation: key.annotation,encryptedKey: ek});
    }
    return this;
  }

  private _cachedPayload?: Promise<Uint8Array>

  get payloadPromise(): Promise<Uint8Array> {
    if( !this._cachedPayload ) {
      if( this.encryptedPayload )
        this._cachedPayload = this.accessKey.etaDecrypt(this.encryptedPayload)
      else
        throw new Error("SharedBox has no payload");
    }
    return this._cachedPayload;
  }

  /**
   * Await and deserialize payload (that should be [MapSerializer] serialized therefore).
   */
  async deserialize<T>(): Promise<T> {
    return await MapSerializer.anyFromBoss(await this.payloadPromise);
  }

  async setPayload(value: Uint8Array): Promise<SharedBox> {
    if (!(this._cachedPayload !== undefined && equalArrays(value, await this._cachedPayload))) {
      if( !this.#mainKey )
        throw new Error("SharedBox is not initialized");
      this.encryptedPayload = await this.#mainKey.etaEncrypt(value);
      this._cachedPayload = Promise.resolve(value);
    }
    return this;
  }

  /**
   * Unlock the shared box using keys from a ring or throw exception.
   * @param keyRing where to get keys to try
   * @return self, unlocked
   * @throws SharedBox.Exception if no one key in the ring opens the box
   */
  async unlockWithRing(keyRing: AnnotatedKeyring): Promise<SharedBox> {
    if( this.#mainKey )
      throw new Error("SharedBox already unlocked");
    const annotations: KeyAnnotation[] = this.accessors.map(k => k.annotation);
    const key = await keyRing.findKey(...annotations);
    if( !key )
      throw new SharedBox.Exception("can't unlock");
    const packed = this.packedAccessors.get(key.annotationLabel);
    if( !packed ) throw new Error("inconsistent SharedBox state (internal error)")
    this.#mainKey = new SymmetricKey({
      keyBytes: await key.etaDecrypt(packed)
    });
    return this;
  }

  /**
   * Unlock the shared box using keys from a ring or throw exception.
   * @param keys to try to unlock with
   * @return self, unlocked
   * @throws SharedBox.Exception if no one key in the ring opens the box
   */
  async unlockWithKeys(...keys: AnnotatedKey[]): Promise<SharedBox> {
    return this.unlockWithRing(new AnnotatedKeyring().addKeys(...keys));
  }

  async toMap(): Promise<BossObject> {
    const sa = new Map<BossPrimitive,Uint8Array>()
    for( const a of this.accessors)
      sa.set(serializeKeyAnnotation(a.annotation), a.encryptedKey)
    return {
      packedAccessors: sa,
      encryptedPayload: this.encryptedPayload
    }
  }

  async pack(): Promise<Uint8Array> {
    return Boss.dump(await this.toMap())
  }

  static async fromMap(source: BossObject): Promise<SharedBox> {
    const sourceAccessors = source.packedAccessors as unknown as Map<BossObject,Uint8Array>;
    const accessors = Array<{annotation: KeyAnnotation,encryptedKey: Uint8Array}>();
    for( const [k,v] of sourceAccessors ) {
      // packed key annotation is not exactly in our native format
      accessors.push({annotation: deserializeKeyAnnotation(k),encryptedKey: v});
    }
    return new SharedBox(accessors, source.encryptedPayload as Uint8Array);
  }

  static async unpack(source: Uint8Array): Promise<SharedBox> {
    const x = await Boss.load(source);
    return this.fromMap(x);
  }

  static async createWith(payload: any): Promise<SharedBox> {
    return SharedBox.createWithPacked(await MapSerializer.toBoss(payload))
  }

  static async createWithPacked<T>(data: Uint8Array): Promise<SharedBox> {
    const sb = new SharedBox([])
    sb.initializeAsNew()
    await sb.setPayload(data)
    return sb;
  }
}