import { trimToSize } from "./StringTools";
import { MyoCloud } from "./MyoCloud";
import { BossObject } from "uparsecjs";

function trm(source?: string): string {
  return trimToSize(source, 8)
}

export class MyoElement {

  id?: number;
  serial?: number;
  uniqueTag?: string;
  createdAt!: Date;
  tag1?: string;
  tag2?: string;
  tag3?: string;
  revision?: number;
  head!: Uint8Array;

  constructor(private cloud: MyoCloud,elementData: BossObject) {
    this.updateFrom(elementData);
  }

  updateFrom(elementData: BossObject): void {
    Object.assign(this, elementData);
  }

  toString() {
    return `E[${this.id}/${this.serial}:${trm(this.uniqueTag)}:${trm(this.tag1)}:${trm(this.tag2)}:${trm(this.tag3)}` +
      `|${this.revision},h=${this.head.length}b]`;
  }
}