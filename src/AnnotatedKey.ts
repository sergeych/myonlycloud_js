/* eslint-disable @typescript-eslint/no-use-before-define */
import { AbstractKey, encode64, PrivateKey, PublicKey, randomBytes, SHA, SHAStringType, SymmetricKey } from "unicrypto";
import {
  BossObject, equalArrays,
  UniversalKey,
  UniversalPasswordKey,
  UniversalPrivateKey,
  UniversalSymmetricKey,
  utf8ToBytes
} from "uparsecjs";
import instantiate = WebAssembly.instantiate;
import { PasswordKeyGenerator } from "./PasswordKeyGenerator";
import { encode64Compact } from "./tools";
import { MapSerializable, MapSerializer, Serializable } from "./MapSerializer";

export interface SymmetricKeyAnnotation {
  type: "SymmetricKeyAnnotation";
  id: Uint8Array;
}

export interface RSAKeyAnnotation {
  type: "RSAKeyAnnotation";
  id: Uint8Array;
}

/**
 * Supportad hashes used in annotation key didgests, mainly, in password
 * generators PBKDF2 and like
 */
export type AnnotatedKeyDigestType = "SHA256" | "SHA512" | "SHA3_256" | "SHA3_384";

export interface PasswordKeyAnnotation {
  type: "PasswordKeyAnnotation";
  id: Uint8Array;
  digest: AnnotatedKeyDigestType;
  rounds: number;
  salt: Uint8Array;
  fullLength: number;
  keyOffset: number;
  keyLength: number;
}

export type KeyAnnotation = PasswordKeyAnnotation | RSAKeyAnnotation | SymmetricKeyAnnotation;

/**
 * Cobvert [KeyAnnotation] fo a serialized form suitable for MyOnlycloud binary serialization.
 * @param annotation to serialize
 */
export function serializeKeyAnnotation(annotation: KeyAnnotation): BossObject {
  const result: BossObject = { ...annotation };
  delete result.type;
  result.$ = annotation.type;
  if ( !!result.digest )
    result.digest = { name: result.digest };
  return result;
}

/**
 * Deserializes MyOnlyCould-serlialized KeyAnnotation
 * @param source
 */
export function deserializeKeyAnnotation(_source: BossObject): KeyAnnotation {
  const source: any = _source;
  const result = { ...source };
  delete result.$;
  result.type = source.$;
  switch (source.$) {
    case "PasswordKeyAnnotation":
      if( ! source?.digest?.name )
        throw new Error("illegal serialized annotation: no digest for password");
      result.digest = source.digest.name;
      break;
    case "SymmetricKeyAnnotation":
    case "RSAKeyAnnotation":
      break;
    default:
      throw new Error("can't deserialize annotated key, wrong type: " + source.$);
  }
  return result;
}

export function annotationLabel(keyAnnotation: KeyAnnotation): string {
  const data: any = { ...keyAnnotation, id: encode64(keyAnnotation.id) };
  if (keyAnnotation.type == "PasswordKeyAnnotation")
    data.salt = encode64(keyAnnotation.salt);
  const parts = Object.getOwnPropertyNames(data)
    .sort((a, b) => a.localeCompare(b))
    .map(name => `${name}=${data[name]}`);
  return parts.join(":");
}


export type SupportedAnnotatedKeys = SymmetricKey | PrivateKey | PublicKey;

@Serializable
export class AnnotatedKey implements MapSerializable {

  static Exception = class extends Error {
  }

  constructor(
    public readonly key: SupportedAnnotatedKeys,
    public readonly annotation: KeyAnnotation
  ) {
  }

  private _label?: string;

  get annotationLabel(): string {
    if (!this._label) this._label = annotationLabel(this.annotation);
    return this._label;
  }

  /**
   * The promise to the separately packed key. To pack the whole annotated key use
   * [[MapSerializer.toBoss]]
   */
  get packedKey(): Promise<Uint8Array> {
    switch (this.annotation.type) {
      case "PasswordKeyAnnotation":
      case "SymmetricKeyAnnotation":
        return Promise.resolve((this.key as SymmetricKey).pack())
      case "RSAKeyAnnotation":
        if (this.key instanceof PrivateKey)
          return this.key.pack();
        if (this.key instanceof PublicKey)
          return this.key.pack();
    }
    throw new Error("inconsistent key");
  }

  etaEncrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    switch (this.annotation.type) {
      case "RSAKeyAnnotation":
        if (this.key instanceof PrivateKey)
          return this.key.publicKey.encrypt(ciphertext)
        if (this.key instanceof PublicKey)
          return this.key.encrypt(ciphertext);
        break;
      case "SymmetricKeyAnnotation":
      case "PasswordKeyAnnotation":
        if (this.key instanceof SymmetricKey)
          return this.key.etaEncrypt(ciphertext);
        break;
    }
    throw new AnnotatedKey.Exception(`invalid key type: ${typeof this.key}, expected ${this.annotation.type}`);
  }

  etaDecrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    switch (this.annotation.type) {
      case "RSAKeyAnnotation":
        if (this.key instanceof PublicKey)
          throw new AnnotatedKey.Exception("can't decrypt with public key, private is required")
        if (this.key instanceof PrivateKey)
          return this.key.decrypt(plaintext);
        break;
      case "SymmetricKeyAnnotation":
      case "PasswordKeyAnnotation":
        if (this.key instanceof SymmetricKey)
          return this.key.etaDecrypt(plaintext);
        break;
    }
    throw new AnnotatedKey.Exception(`invalid key type: ${typeof this.key}, expected ${this.annotation.type}`);
  }

  matchesAnnotation(annotation: KeyAnnotation): boolean {
    if (
      annotation.type == "PasswordKeyAnnotation" && this.annotation.type == "SymmetricKeyAnnotation" ||
      annotation.type == "SymmetricKeyAnnotation" && this.annotation.type == "PasswordKeyAnnotation"
    ) {
      return equalArrays(annotation.id, this.annotation.id)
    }
    if (this.annotationLabel == annotationLabel(annotation)) return true;
    return false
  }

  equalsTo(otherKey: AnnotatedKey | PrivateKey | PublicKey): boolean {
    const other = otherKey instanceof AnnotatedKey ? otherKey : AnnotatedKey.fromAsymmetricKey(otherKey)
    if (!this.matchesAnnotation(other.annotation))
      return false;
    switch (this.annotation.type) {
      case "RSAKeyAnnotation": {
        const k1 = this.key;
        const k2 = other.key;
        if (k1 instanceof PublicKey && k2 instanceof PublicKey ||
          k1 instanceof PrivateKey && k2 instanceof PrivateKey)
          return true;
        return false;
      }
      case "PasswordKeyAnnotation":
      case "SymmetricKeyAnnotation": {
        const k1 = this.key as SymmetricKey
        const k2 = other.key as SymmetricKey
        return equalArrays(k1.pack(), k2.pack());
      }
    }
  }

  static createRandomSymmetric(): AnnotatedKey {
    return new AnnotatedKey(
      new SymmetricKey(),
      { type: "SymmetricKeyAnnotation", id: randomBytes(32) }
    );
  }

  static async createPrivate(bitStrength = 4096): Promise<AnnotatedKey> {
    const key = await PrivateKey.generate({ strength: bitStrength });
    return new AnnotatedKey(
      key,
      { type: "RSAKeyAnnotation", id: key.publicKey.longAddress.bytes }
    );
  }

  static async fromPassword(
    password: string,
    salt: Uint8Array | string,
    rounds: number,
    digest: AnnotatedKeyDigestType = "SHA256"
  ): Promise<AnnotatedKey> {
    return (await PasswordKeyGenerator.generateKeys(password, 1, salt, rounds, digest, 32))[0];
  }

  static fromAsymmetricKey(key: PublicKey | PrivateKey): AnnotatedKey {
    const address = key instanceof PublicKey ? key.longAddress : key.publicKey.longAddress;
    return new AnnotatedKey(key, {
      type: "RSAKeyAnnotation",
      id: address.bytes
    });
  }

  static async fromUniversalKey(uk: UniversalKey): Promise<AnnotatedKey> {
    if (uk instanceof UniversalPrivateKey)
      return new AnnotatedKey(uk.privateKey, {
        type: "RSAKeyAnnotation",
        id: uk.publicKey.longAddress.bytes
      })

    if (uk instanceof UniversalSymmetricKey)
      return new AnnotatedKey(new SymmetricKey({ keyBytes: uk.keyBytes }), {
        type: "SymmetricKeyAnnotation",
        id: uk.tag.id
      });

    if (uk instanceof UniversalPasswordKey) {
      const pko = uk.tag.pkdOptions;
      return new AnnotatedKey(await uk.symmetricKey, {
        type: "PasswordKeyAnnotation",
        id: uk.tag.id,
        digest: toAnnotatedKeyHashType(pko.hashAlgorithm),
        fullLength: pko.kdfLength,
        keyLength: pko.keyLength,
        keyOffset: pko.keyOffset,
        rounds: pko.rounds,
        salt: pko.salt
      })
    }
    throw new this.Exception(`unsupported universal key type: ${typeof uk}`)
  }

  async toMap(): Promise<BossObject> {
    return {
      $: 'AnnotatedKey',
      key: await MapSerializer.serialize(this.key),
      annotation: serializeKeyAnnotation(this.annotation)
    }
  }

  static async fromMap(source: BossObject): Promise<AnnotatedKey> {
    const key = await MapSerializer.deserialize(source.key as BossObject);
    const annotation = deserializeKeyAnnotation(source.annotation as BossObject);
    return new AnnotatedKey(key as SupportedAnnotatedKeys, annotation);
  }
}

/**
 * Convert `unicrypto` hash algorithm name to the the annotated key's label. See [[SHA]] for example.
 * @param hashAlgorithm as recognized by unicrypto
 * @return converted label
 * @throws AnnotatedKey.Exception if the nane of the hash is not supported bu annotated keys infrastructure
 */
export function toAnnotatedKeyHashType(hashAlgorithm: SHAStringType): AnnotatedKeyDigestType {
  switch (hashAlgorithm) {
    case "sha256":
      return "SHA256";
    case "sha384":
      return "SHA3_384";
    case "sha512":
      return "SHA512";
    case "sha3_256":
      return "SHA3_256";
    case "sha3_384":
      return "SHA3_384";
  }
  throw new AnnotatedKey.Exception(`AnnotatedKey: from universal: unsupported hash type ${hashAlgorithm}`)
}

/**
 * Convert annotated key hash type tag to a string that `unicrypto` library supports in its [[SHA]] module/
 * @param algorithm as specified in annotated keys, for example in [[PasswordKeyAnnotation]]
 * @return string with hash type that `unicrypto` [[SHA]] understands.
 */
export function fromAnnotatedKeyHashType(algorithm: AnnotatedKeyDigestType): SHAStringType {
  switch (algorithm) {
    case "SHA256":
      return "sha256";
    case "SHA512":
      return "sha512";
    case "SHA3_256":
      return "sha3_256";
    case "SHA3_384":
      return "sha3_384";
  }
  throw new Error("invalid argument (unknown annotated key hash type): " + algorithm);
}

export function hashDigest(algorithm: AnnotatedKeyDigestType, data: Uint8Array | string): Promise<Uint8Array> {
  return SHA.getDigest(fromAnnotatedKeyHashType(algorithm), data instanceof Uint8Array ? data : utf8ToBytes(data));
}

export async function hashDigest64(algorithm: AnnotatedKeyDigestType, data: Uint8Array | string): Promise<string> {
  return encode64(await hashDigest(algorithm, data));
}

export async function hashDigest64Compact(algorithm: AnnotatedKeyDigestType, data: Uint8Array | string): Promise<string> {
  return encode64Compact(await hashDigest(algorithm, data));
}
