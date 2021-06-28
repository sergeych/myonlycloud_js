
let defaultTestMode = false;

// try {
  if (window && window?.location?.hostname.startsWith("localhost"))
    defaultTestMode = true;
// }
// catch(e) {
//   if( e instanceof ReferenceError )
//     defaultTestMode = false
//   else
//     throw e
// }

let overrideTestMode: boolean | undefined;

export class Config {

  static get testMode(): boolean | undefined {
    return overrideTestMode ?? defaultTestMode;
  }

  static set testMode(value: boolean | undefined) {
    overrideTestMode = value;
  }
}