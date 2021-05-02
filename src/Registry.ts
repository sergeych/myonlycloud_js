import { MyoCloud } from "./MyoCloud";
import { SharedBox } from "./SharedBox";
import { CompletablePromise, concatenateBinary, utf8ToBytes } from "uparsecjs";
import { AnnotatedKeyring } from "./AnnotatedKeyring";
import { AnnotatedKey, hashDigest64Compact } from "./AnnotatedKey";
import { CaseObject, MapSerializer } from "./MapSerializer";
import { Boss, encode64 } from "unicrypto";
import { binaryDump } from "uparsecjs/dist/dumps";

interface RegistrySource {
  tagsSalt?: Uint8Array;
  keyring: AnnotatedKeyring;
  storageKey: AnnotatedKey;
};

class RegistryData extends CaseObject {

  source!: RegistrySource;

  async scramble(tag: string): Promise<string> {
    const source= this.source;
    if (!source.tagsSalt)
      throw new Error("registry not properly initialized: no tagsSalt");
    const buffer = concatenateBinary(source.tagsSalt, utf8ToBytes(tag.trim()));
    return await hashDigest64Compact("SHA3_256", buffer);
  }
}

AnnotatedKeyring;
MapSerializer.registerCaseObject(RegistryData, "Registry");


export class Registry {

  readonly ready = new CompletablePromise();
  private registryTag!: string;
  private backupRegistryTag!: string;
  private data!: RegistryData;
  #passwordStorageKey: AnnotatedKey;

  constructor(private cloud: MyoCloud, storageKey: AnnotatedKey) {
    this.#passwordStorageKey = storageKey;
    this.initialize();
  }

  private async initialize() {
    try {
      this.registryTag = await MyoCloud.simpleScramble("registry1");
      this.backupRegistryTag = await MyoCloud.simpleScramble("registry1_backup");
      console.log("Looking for registry");
      const element = await this.cloud.elementByUniqueTag(this.registryTag) ??
        await this.cloud.elementByUniqueTag(this.backupRegistryTag);
      if (!element) {
        throw new Error("create registry is not yet implemented");
      }
      console.log("found registry element:" + element);
      const packedRegistry = await this.#passwordStorageKey.etaDecrypt(element.head);
      // console.log("pr\n", encode64(packedRegistry));
      this.data = await MapSerializer.fromBoss(packedRegistry);
      // console.log(">>", this.data);
      // console.log(">>", this.data.source.keyring.allKeys().map(x => x.key.annotationLabel));
      // console.log("!>", BossLoad(MapSerializer.deserializeAny(element.head));
      this.ready.resolve();
    }
    catch(e) {
      this.ready.reject(e);
    }
  }

  _mainKeyring?: AnnotatedKeyring;

  get mainKeyring() {
    if( !this._mainKeyring)
      this._mainKeyring = this.data.source.keyring.clone().addKeys(this.data.source.storageKey);
    return this._mainKeyring;
  }

  async scramble(tag: string): Promise<string> {
    return this.data.scramble(tag);
  }
}