import { SymmetricKey } from "unicrypto";
import { CloudElement, LO, Tags } from "./CloudData";
import { CloudActions } from "./DB";

const defaultLO: LO = { limit: 100, offset: 0 };

export interface StoredElement extends CloudElement {
  localId?: number;
  cloudAction?: CloudActions;
  data: Uint8Array;
}

export interface EDBInsatnce {

  create(item: StoredElement): Promise<StoredElement>;
  update(item: StoredElement): Promise<StoredElement>;

  getByUniqueId(uniqueId: string): StoredElement | undefined;

  // getByRemoteId(remoteId: number): EDBItem | undefined;
  getById(localId: number): Promise<StoredElement | undefined>;

  findLocal(lo: LO): Promise<StoredElement>[];

  findBy(params: Tags & LO): Promise<StoredElement>[];

  findByAny(params: Tags & LO): Promise<StoredElement>[];

  getValue(name: string): Promise<Uint8Array | undefined>;
  setValue(name: string,data?: Uint8Array): Promise<void>;

  scramble(key: string): Promise<string>;
}

export class EDBException extends Error {
}

export class EDBEncryptionError extends EDBException {
  constructor(text?: string) {
    super(text ?? "EDB encryption failed");
  }
}

export class EDBNotInitialized extends EDBException {
  constructor() {
    super("EDB is not initialized");
  }
}

export class EDBNotFound extends EDBException {
}

export class EDBAlreadyExists extends EDBException {
  constructor(text?: string) {
    super(text ?? "instance already created. Call deleteIfExists() first")
  }
}

export interface EDB {
  /**
   * Check that some database present. For example:
   * ```
   * const name="fooDB";
   * let instance?: EDBInstance;
   * if( await edb.exists(name) ) {
   *   while( !instance ) {
   *     try {
   *       const password = await getKey(name,"open existing db);
   *       instance = edb.open(key);
 *       }
   *     catch(e) {
   *       if( e instanceof EDBEncryptionError)
   *         errorNotification("wrong password")
   *       else
   *         throw e;
   *     }
   *   }
   * }
   * else {
   *   instance = edb.createNew(name,await getKey("create new db"));
   * }
   * ```
   * @param name EDB name
   */
  exists(name: string): Promise<boolean>;

  /**
   * Open existing EDB using a key. It should exist and the key be matching or it will throw exception.
   *
   * @param name EDB name
   * @param key
   * @throws EDBEncryptionError
   * @throws EDBNotFound
   */
  open(name: string,key: SymmetricKey): Promise<EDBInsatnce>;

  deleteIfExists(name: string): Promise<void>;

  /**
   * Create new EDB instance, if there might be another instance already created call [[deleteIfExists]].
   * @param name EDB name
   * @param key to encrypt it with
   * @throws EDBAlreadyExists
   */
  createNew(name: string, key: SymmetricKey): Promise<EDBInsatnce>;
}