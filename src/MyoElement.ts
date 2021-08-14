import { trimToSize } from "./StringTools";
import { MyoCloud } from "./MyoCloud";
import { BossObject } from "uparsecjs";
import { CloudElement } from "./CloudData";

function trm(source?: string): string {
  return trimToSize(source, 8)
}

export class MyoElement implements CloudElement {

  id?: number;
  serial?: number;
  uniqueTag?: string;
  createdAt!: Date;
  tag1?: string;
  tag2?: string;
  tag3?: string;
  revision?: number;
  head!: Uint8Array;

  constructor(readonly cloud: MyoCloud,elementData: BossObject) {
    this.updateFrom(elementData);
  }

  updateFrom(elementData: BossObject): void {
    Object.assign(this, elementData);
    // normalize undefineds from nulls:
    if( this.uniqueTag === null ) this.uniqueTag = undefined;
    if( this.tag1 === null ) this.tag1 = undefined;
    if( this.tag2 === null ) this.tag2 = undefined;
    if( this.tag3 === null ) this.tag3 = undefined;
  }

  toString() {
    return `E[${this.id}/${this.serial}:${trm(this.uniqueTag)}:${trm(this.tag1)}:${trm(this.tag2)}:${trm(this.tag3)}` +
      `|${this.revision},h=${this.head.length}b]`;
  }
}
