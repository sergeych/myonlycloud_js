
let defaultTestMode = false;

if( window && window?.location?.hostname.startsWith("localhost"))
  defaultTestMode = true;

let overrideTestMode: boolean | undefined;

export class Config {

  static get testMode(): boolean | undefined {
    return overrideTestMode ?? defaultTestMode;
  }

  static set testMode(value: boolean | undefined) {
    overrideTestMode = value;
  }
}