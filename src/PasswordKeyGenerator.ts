import {
  AnnotatedKey,
  AnnotatedKeyDigestType,
  fromAnnotatedKeyHashType, hashDigest,
  hashDigest64, PasswordKeyAnnotation
} from "./AnnotatedKey";
import { equalArrays, utf8ToBytes } from "uparsecjs";
import { pbkdf2, SymmetricKey } from "unicrypto";

/**
 * PBKDF2 derivation parameters
 */
export interface DerivationParams {
  digest: AnnotatedKeyDigestType;
  salt: Uint8Array;
  rounds: number;
  fullLength: number;
}

/**
 * A label internally used to cache generated PBKDF2 arrays
 * @param params
 */
async function derivationLabel(params: DerivationParams): Promise<string> {
  const saltDigest = await hashDigest64("SHA3_256", params.salt);
  return `${params.digest}:${saltDigest}|${params.rounds}|${params.fullLength}`;
}

const recycler = new Map<string,PasswordKeyGenerator>();

/**
 * Generates keys for same passwords and cache generated arrays. One password may require
 * generation of different keys and maybe with different generation parameters, so we cach it
 * inside.
 *
 * Use [[generateKeys]] to get the keys. Do not instantiate this class manually.
 */
export class PasswordKeyGenerator {

  // Cached generated (or being generated) PBKDF arrays using derivationLabels:
  private readonly results = new Map<string, Promise<Uint8Array>>()

  private constructor(private readonly password: string) {
  }

  private async derive(params: DerivationParams): Promise<Uint8Array> {
    const label = await derivationLabel(params);
    let promise = this.results.get(label);
    if (!promise) {
      promise = pbkdf2(fromAnnotatedKeyHashType(params.digest), {
        password: this.password,
        salt: params.salt,
        rounds: params.rounds,
        keyLength: params.fullLength
      });
    }
    return promise;
  }

  /**
   * Generate one or more keys from this password. If such a key is already generated or is being generated,
   * it will be automatically reused. Creates AnnotatedKeys that could be later restored from the passowrd using
   * parameters saved inside their instances (see [[PasswordKeyAnnotation]]).
   *
   * Not that the cryptographically independent ID for annotation is also derived from the password and could be
   * safely disclosed to distinguish _keys_ but not disclosing info of the _password_ used.
   *
   * @param count number of keys to generated
   * @param salt PBKDF2 salt
   * @param rounds PBKDF2 rounds
   * @param idLength size of id that is also dervived from the password.
   * @param digest hash algorithm used in PBKDF2
   */
  public async generateKeys(
    count: number,
    salt: Uint8Array | string,
    rounds: number,
    idLength = 32,
    digest: AnnotatedKeyDigestType = "SHA256"
  ): Promise<AnnotatedKey[]> {
    const fullLength = count * 32 + idLength;
    const preparedSalt = salt instanceof Uint8Array ? salt : await hashDigest("SHA256", salt);
    const dp: DerivationParams = { digest, salt: preparedSalt, rounds, fullLength };
    const data = await this.derive(dp);
    const id = data.slice(fullLength - idLength);
    let offset = 0

    const keys: AnnotatedKey[] = [];
    while (count-- > 0) {
      keys.push(
        new AnnotatedKey(
          new SymmetricKey({ keyBytes: data.slice(offset, offset + 32) }),
          {
            id,
            rounds,
            digest,
            type: "PasswordKeyAnnotation",
            salt: preparedSalt,
            fullLength,
            keyOffset: offset,
            keyLength: 32,
          }
        ));
      offset += 32;
    }
    return keys;
  }

  private async restoreKey(annotation: PasswordKeyAnnotation): Promise<AnnotatedKey|undefined> {
    // re-derive:
    const fullLength = annotation.fullLength;
    const params: DerivationParams = {
      fullLength,
      salt: annotation.salt,
      digest: annotation.digest,
      rounds: annotation.rounds
    };

    const data = await this.derive(params);

    // extract and check id, if the password is the same, id will be the same too:
    const id = data.slice(fullLength-annotation.id.length);
    if( equalArrays(id, annotation.id))
      return new AnnotatedKey(
        new SymmetricKey({
          keyBytes: data.slice(annotation.keyOffset, annotation.keyOffset + annotation.keyLength)
        }), annotation);

    // password is wrong
    return undefined;
  }

  /**
   * Caching password keys generator. Generates one or more keys for a given password and generation parameters
   * reusing matching keys being generated (it is performed in a worker) or already generated. Use [[clear()]]
   * to drop the cache for security reasons.
   * @param password
   * @param count
   * @param salt
   * @param rounds
   * @param idLength
   * @param digest
   */
  static async generateKeys(
    password: string,
    count: number,
    salt: Uint8Array | string,
    rounds: number,
    digest: AnnotatedKeyDigestType = "SHA256",
    idLength = 32
  ): Promise<AnnotatedKey[]> {
    return this.recyclableGenerator(password).generateKeys(count,salt,rounds,idLength,digest);
  }

  static recyclableGenerator(password: string): PasswordKeyGenerator {
    let pg = recycler.get(password);
    if( !pg ) {
      pg = new PasswordKeyGenerator(password);
      recycler.set(password, pg);
    }
    return pg;
  }

  /**
   * Forget everything about generated keys. New keys will be re-derived on firts request.
   * It is safe to call clear immediately after [[generateKeys]].
   */
  static clear() {
    recycler.clear();
  }

  /**
   * Try to restore the key for a given password and annotation, which contains all necessary derivation
   * parameters. Note that derivation contains also id, so we can check that derived key is what is expected,
   * and retunr undefined if the password does not match.
   * @param password to derive from
   * @param annotation
   * @return promise with derived key if the password is ok otherwise undefined.
   */
  static restoreKey(password: string,annotation: PasswordKeyAnnotation): Promise<AnnotatedKey|undefined> {
    if( annotation.type != "PasswordKeyAnnotation")
      throw new AnnotatedKey.Exception(`annotatin of type ${annotation.type} can;t be used to regeneratoe password key`);
    return this.recyclableGenerator(password).restoreKey(annotation);
  }
}

