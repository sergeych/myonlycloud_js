import { MapSerializer } from "./MapSerializer";
import { SharedBox } from "./SharedBox";
import { MagickRecord } from "./MagickRecord";
import { SignedRecord } from "unicrypto";
import { CloudElement } from "./CloudData";
import { MyoCloud } from "./MyoCloud";
import ownKeys = Reflect.ownKeys;

export interface StrategyOverride {
  strategy: "override";
}

export interface StrategyAddRevision {
  strategy: "addRevision";
  maxRevisions: number;
}

export interface StrategyMerge {
  strategy: "merge",

  merge<T extends CloudObject<any>>(latestObject: T): Promise<T>;
}

export interface StrategyError {
  strategy: "error";
}

export type CloudMergeStrategy = StrategyOverride | StrategyAddRevision | StrategyMerge | StrategyError;

export class CloudObjectError extends Error {
}

export class CloudObjectFormatError extends CloudObjectError {
}

export class CloudObjectNotLoaded extends CloudObjectError {
}

export class CloudObject<T> {

  private _data?: T;
  private _sharedBox?: SharedBox;
  private _element?: CloudElement;
  private _signedRecord?: SignedRecord;
  private _service?: MyoCloud;

  constructor(protected params: { labels: Record<string,{encrypted?: boolean,signed?: boolean}> } & CloudMergeStrategy =
                {
                  labels: {
                    sb1: {encrypted: true},
                    ssb1: {encrypted: true, signed: true},
                    sr1: {signed: true}
                  },
                  strategy: "error"
                }
  ) {
  }

  async loadFrom(element: CloudElement,service: MyoCloud): Promise<CloudObject<T>> {
    this._service = service;
    if (!element.head)
      throw new CloudObjectFormatError("head is empty");
    const record = await MagickRecord.unpack(element.head!, ...ownKeys(this.params.labels) as string[]);
    const ll = this.params.labels[record.label];
    this._service = service;
    if( ll.encrypted && ll.signed ) {
      this._signedRecord = await SignedRecord.unpack(record.payload as Uint8Array);
      this._sharedBox = await MapSerializer.deserialize(this._signedRecord.payload);
    }
    else if( ll.encrypted && !ll.signed ) {
      this._signedRecord = undefined;
      this._sharedBox = record.payload as SharedBox;
    }
    else if( !ll.encrypted && ll.signed) {
      this._signedRecord = await SignedRecord.unpack(record.payload as Uint8Array);
      this._sharedBox = undefined;
      this._data = await MapSerializer.deserializeAny(this._signedRecord.payload);
    }
    if( !this._data) {
      if (!this._sharedBox) throw new CloudObjectFormatError(`no data found in ${this._element}`);
      await this._sharedBox.unlockWithRing(await service.mainRing);
      this._data = await MapSerializer.anyFromBoss(await this._sharedBox.payloadPromise);
    }
    // TODO: store in local storage!
    return this;
  }

  get loaded(): boolean { return !!this._sharedBox; }

  get data(): T {
    if( !this._data )
      throw new CloudObjectNotLoaded();
    return this._data;
  }

}


