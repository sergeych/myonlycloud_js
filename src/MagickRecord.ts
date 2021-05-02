import { Boss } from "unicrypto";
import { MapSerializer } from "./MapSerializer";
import { BossObject } from "uparsecjs";

export interface MagicRecordData<T> {
  label: string;
  payload: T;
}

export class MagickRecord {

  static Exception = class extends Error {};

  static async pack<T>(record: MagicRecordData<T>): Promise<Uint8Array> {
    const bw = new Boss.Writer();
    bw.write(record.label)
    bw.write(await MapSerializer.serializeAny(record.payload));
    return bw.get();
  }

  /**
   * Unpack magick framed record optionally checking the label.
   * @param packed
   * @param labels if at least one label presents, will not unpack the rest of the record unless the loaded label is
   *        listed among lavels.
   * @throws MagickRecord.Exception if the label is not present in an non-empty labels.
   */
  static async unpack<T>(packed: Uint8Array, ...labels: string[]): Promise<MagicRecordData<T>> {
    const br = new Boss.Reader(packed);
    const label: string = br.read();
    if( labels.length && !labels.includes(label) )
      throw new MagickRecord.Exception(`label ${label} does not belong to allowed: ${labels}`)
    return { label, payload: await MapSerializer.deserializeAny(br.read() as BossObject)};
  }
}