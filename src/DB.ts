import {
  EDB,
  EDBEncryptionError,
  EDBException,
  EDBInsatnce,
  EDBNotFound,
  StoredElement
} from "./EncryptedDB";
import { SymmetricKey } from "unicrypto";
import { CompletablePromise } from "uparsecjs";

const localSettingsKey = "..localSettings";

export const caCreate = "caCreate";
export const caUpdate = "caUpdate";
export const caAddRevision = "caAddRevision";
export const caUpdateAttributes = "caUpdateAttributes";
export const caDelete = "caDelete";

export type CloudActions =  typeof caCreate | typeof caUpdate | typeof caAddRevision | typeof caUpdateAttributes |
  typeof caDelete;

export const CloudActionNames = [caCreate, caUpdate, caAddRevision, caUpdateAttributes, caDelete];
Object.freeze(CloudActionNames);


interface LocalDescriptor {

}

export class DB {
  private instance!: EDBInsatnce;
  private _ready = new CompletablePromise<DB>();
  private actionAddRevision!: string;

  private scrampledActions = new Map<string,string>();
  private unscrambpledActions = new Map<string,string>();

  constructor(private edb: EDB) {
  }

  get ready(): Promise<DB> { return this._ready; }

  async openOrCreate(name: string, key: SymmetricKey): Promise<void> {
    if (await this.edb.exists(name)) {
      console.debug("EDB: trying to open existing EDB");
      try {
        this.instance = await this.edb.open(name, key);
      } catch (e) {
        if (e instanceof EDBEncryptionError) {
          console.log("EDB: key does not match, deleting existing db");
          await this.edb.deleteIfExists(name);
        } else throw e;
      }
    }
    if (!this.instance) {
      console.log("EDB: creating new");
      this.instance = await this.edb.createNew(name, key);
    }
    await this.initialize();
  }


  async scramble(source: string): Promise<string> {
    await this.ready;
    return await this.instance.scramble(source);
  }

  private async initialize() {
    for( const a in CloudActionNames) {
      const scrambledA = await this.scramble(a);
      this.scrampledActions.set(a, scrambledA);
      this.unscrambpledActions.set(scrambledA,a);
    }
    this._ready.resolve(this);
  }

  /**
   * @param se
   * @return a COPY of se with encrypted cloudAction!
   * @private
   */
  private encryptAction(se: StoredElement): StoredElement {
    if( !se.cloudAction ) return se;
    const result = {...se, cloudAction: this.scrampledActions.get(se.cloudAction) };
    if(!result.cloudAction)
      throw new EDBException("unknown cloud action: "+se.cloudAction);
    return result as StoredElement;
  }

  /**
   * Decrypt cloudAction IN PLACE!
   * @param se
   * @private
   */
  private decryptAction(se: StoredElement): StoredElement {
    if( !se.cloudAction ) return se;
    se.cloudAction = this.unscrambpledActions.get(se.cloudAction) as CloudActions;
    if( !se.cloudAction ) throw new EDBException("can't descramble cloud action");
    return se;
  }

  async create(se: StoredElement): Promise<StoredElement> {
    await this._ready;
    const result = await this.instance.create(this.encryptAction(se));
    return {...result, cloudAction: se.cloudAction};
  }

  async byLocalId(localId: number): Promise<StoredElement> {
    await this.ready;
    const se = await this.instance.getById(localId);
    if( !se ) throw new EDBNotFound("not floud local id: "+localId);
    return this.decryptAction(se);
  }

  async save(se: StoredElement): Promise<void> {
    await this.ready;
    await this.instance.update(this.encryptAction(se));
  }

}