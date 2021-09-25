import { encode64, PrivateKey, SHA } from "unicrypto";
import { utf8ToBytes } from "uparsecjs";
import { AnnotatedKey } from "./AnnotatedKey";
import { PasswordKeyGenerator } from "./PasswordKeyGenerator";
import { SharedBox } from "./SharedBox";
import { fromBoss } from "./MapSerializer";

/**
 * Key pairs derived from the password to access login key
 */
interface CloudLoginAccessKeys {
  /**
   * This key is used to decrypt other data in the could, except the login private key.
   */
  storageKey: AnnotatedKey;
  /**
   * This key decrypts the login private, stored in the sharedbox in the registration record
   */
  loginAccessKey: AnnotatedKey;
}

/**
 * Keys to access the cloud, derived by successful login.
 */
interface CloudAccessKeys {
  /**
   * This key is used to decrypt other data in the could, except the login private key.
   */
  storageKey: AnnotatedKey;
  /**
   * This key uis decrypted from one stored in the cloud
   */
  loginKey: PrivateKey;
}

/**
 * Calculate parts of MyOnly.cloud login/registration data, e.g. loginHash, loginKey and storageKey.
 */
export class Credentials {
  static deriveLoginHash(login: string): Promise<string> {
    return SHA.getDigest("sha3_384", utf8ToBytes(login.toLowerCase().trim()))
      .then(bytes => encode64(bytes));
  }

  static async deriveKeysFromPassword(password: string, rounds = 150000): Promise<CloudLoginAccessKeys> {
    const passwordKeys = await PasswordKeyGenerator.generateKeys(
      password,
      2,
      utf8ToBytes("myo.cloud.login"),
      rounds,
      "SHA256"
    )

    return {
      loginAccessKey: passwordKeys[0],
      storageKey: passwordKeys[1]
    };
  }

  static async decryptCloudKeys(password: string, encryptedKey: Uint8Array): Promise<CloudAccessKeys> {
    const sb: SharedBox = await SharedBox.unpack(encryptedKey);
    const passwordKeys = await Credentials.deriveKeysFromPassword(password);
    await sb.unlockWithKeys(passwordKeys.loginAccessKey);
    // console.log(await Boss.load(await sb.payloadPromise));
    return {
      loginKey: await fromBoss(await sb.payloadPromise, "loginKey"),
      storageKey: passwordKeys.storageKey
    };
  }

  static async encryptLoginKey(loginKey: PrivateKey, password: string): Promise<Uint8Array> {
    // key derivation in parallel
    const keysPromise = Credentials.deriveKeysFromPassword(password);
    // ... with sharedbox creation
    const sb = await SharedBox.createWith({loginKey: loginKey});
    const keys = await keysPromise;
    await sb.addKeys(keys.loginAccessKey);
    return await sb.pack();
  }

  // static async encryptCloudKeys(password: string,loginKeyPromise: Promise<PrivateKey>): Promise<Uint8Array> {
    // return SharedBox.fromMap(mapOf(
    //   "loginKey" to loginKey
  // )).toBoss()
  //   const passwordKeys = await Credentials.deriveKeysFromPassword(password)
  //   const sb = new SharedBox()
  // }
}

// MapSerialization initialization: do not remove
SharedBox;
