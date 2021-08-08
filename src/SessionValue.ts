import { BossPrimitive, ParsecSessionStorage } from "uparsecjs";
import { Boss, decode64, encode64 } from "unicrypto";

export class SessionValue<T extends BossPrimitive> {

  cached?: BossPrimitive;

  constructor(private pss: ParsecSessionStorage, private key: string) {
  }

  get value(): T | undefined {
    if (!this.cached) {
      const packed = this.pss.getItem(this.key);
      if (!packed) return undefined;
      this.cached = Boss.load(decode64(packed));
    }
    return this.cached as T;
  }

  set value(newValue: T | undefined) {
    this.cached = newValue;
    if (newValue == undefined)
      this.pss.removeItem(this.key);
    else
      this.pss.setItem(this.key, encode64(Boss.dump(newValue)));
  }

  clear() { this.value = undefined; }
}
