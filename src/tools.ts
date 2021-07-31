import { AbstractKey, encode64, PrivateKey, PublicKey, SymmetricKey } from "unicrypto";
import { AnnotatedKey } from "./AnnotatedKey";
import { equalArrays } from "uparsecjs";

export function encode64Compact(data: Uint8Array): string {
  const source = encode64(data);
  let last = source.length - 1;
  while (last > 0 && source.charAt(last) == "=") last--;
  return source.slice(0, last + 1);
}

/**
 * compare most keys used in Universa and parsec for equality. This is different from key matching, for example,
 * public and private key from the same pair __are matching but not equal__. Be careful.
 *
 * Also, it properly compares ant consider equal keys when one is wrapped in AnnotatedKey. E.g AbstractKey is
 * equal to [AnnotatedKey] when its the [AnnotatedKey.key] is equal to AnnotatedKey.
 *
 * @return true if keys are equal.
 */
export function equalKeys(k1: AbstractKey | AnnotatedKey, k2: AbstractKey | AnnotatedKey) {

  if( k1 instanceof AnnotatedKey && k2 instanceof AnnotatedKey)
    return k1.equalsTo(k2);

  const a = k1 instanceof AnnotatedKey ? k1.key : k1;
  const b = k2 instanceof AnnotatedKey ? k2.key : k2;

  if( a instanceof SymmetricKey && b instanceof SymmetricKey)
    return equalArrays(a.pack(),b.pack())

  if( a instanceof PublicKey && b instanceof PublicKey)
    return equalArrays(a.longAddress.bytes,b.longAddress.bytes);

  if( a instanceof PrivateKey && b instanceof PrivateKey)
    return equalArrays(a.publicKey.longAddress.bytes,b.publicKey.longAddress.bytes);

  return false;
}

/**
 * Checks that "obj == {}" in a right manner.
 * @param obj to test for emptiness
 * @return true if object _has no keys_. Note that object with keys set to undefined is not considered empty.
 */
export function isEmptyObject(obj: any): boolean {
  return Object.keys(obj).length == 0;
}

/**
 * Extended emptiness check that correctly works with regular objects `{}` and Map<K,V> instances as well. The empty
 * map is not, technically, an empty object, though in some browsers its Object.keys returns empty array, so use
 * this function instead.
 * @param obj object to check for emptiness.
 * @return true if object has no key or is an instance of the empty map
 */
export function isEmptyObjectOrMap(obj: any): boolean {
  if( obj instanceof Map ) return obj.size == 0;
  return isEmptyObject(obj);
}
