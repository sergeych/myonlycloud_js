import { decode64, encode64, PrivateKey } from "unicrypto";
import { AnnotatedKey, Credentials, fromBoss, SharedBox } from "../src";

describe('cloudservice', () => {

  it("calculates credentials", async () => {
    const expectedLoginHash = "0ew9aOIoGBhzCOsWsIVOs+HRqPFaXCyePKbyf7sW1GOR5aES3UjZkt5A0OPmy/Ad"
    const expectedLoginKey = "l0fTLYYRItVzMME6UPKgkcSr5Yw1kAAhjAyYCxyoHAU="
    const expectedStorageKey = "iKEnKw9tYdpYtLa+nSklLYRekQFA2ZHPJ2Y+mZ+7BfQ="

    const kk = await Credentials.deriveKeysFromPassword("qwert12345.");

    expect(await Credentials.deriveLoginHash("test_21")).toBe(expectedLoginHash);
    expect(encode64(await kk.loginAccessKey.packedKey)).toBe(expectedLoginKey);
    expect(encode64(await kk.storageKey.packedKey)).toBe(expectedStorageKey);
  })

  const sampleLoginObject = decode64("H4NlbmNyeXB0ZWRQYXlsb2FkxF4Cuxzgeaxa+BEjWtpyQNy1DdsomdNOkTKm8ryRO7k1nn2b6U6ldvOp/jQa9cKrwjqSF5A5n4WjMWD09pSIfKdyzvwZ1dPNmAB3o8jWJPyIPg8lGp8VBkm7TVzofV3KqmmN8XsQ6uCnEq9eG2rik7wpWrXeGHRe2MxvKvhNgyi2/Skpj8+L4tGvO1przlYAaDZ1OhBqty4VWp7wsGbeTKH7X5jXRGdESgXb9njRJvCmn4kY80i5Lg25nZGjn999/31gnMd2TKwQp3KCUaBfbpqcoGBqgXbYu/hF+mVYDKUVGv4ZXYIM+hCR+SrHGQRrMjebMoA7jEtOM/CovHZvMbSPnnChMwxGVrs6ofc+0cJe8OnJqw0GQGadaL0VykEMFHhwhbqsPIucMV3S4n3g5UWatEiA6jn9hIuWXKnw5ljxnHwtaJMsD+abxpAnA4kBZJNQb1FqpuVUknmhCB60hisIjVZr3WxbM+vm+fU/JtaGke3rqCjlzC1xMyULW6sUxG/2/I/PV0xwbSnOCkkgdTddJJY4k+XLFcxw1gKzzKMQCs+SRPOdRQZM2dM8tkToFPCQYKAO9IhrqyaEyJeJ9A2w4ITWxftbgBgp9oHRlnSOVyw6ShJ7HdTpx7dC5W1secqUlFnhVaZJUCczIR5a0unx6JKNqU3idxkkzB4ipA8u+33Z0YRif8oWJVEjHiOdlRSfEKBzg42pkjMUkNEJvDsdSNlma4jfJmT/7e/+1vSOT0IDXzBn6xl60M8s8fDuzgyWucgLsfXzTL+37Zf2mmZrKTDJhFLGNstq4fwEE4byCyRLU2hhcmVkQm94e3BhY2tlZEFjY2Vzc29ycw9HS2tleUxlbmd0aLggI3NhbHR8bXlvLmNsb3VkLmxvZ2luJatQYXNzd29yZEtleUFubm90YXRpb24zZGlnZXN0DyNuYW1lM1NIQTI1NlNmdWxsTGVuZ3RouGATaWS8IGpmiLRmmhRoBzuuH+7Ou8lR5o97qhA6nOHsfiOY5gSaS2tleU9mZnNldAAzcm91bmRzyPBJArxQ2++Qq5jOy6uEsqzivMncSkkZwqBj81kpxvDCTw8Y6yAcXjkQjQNp8Plcbx10FOQfbb8RF8a/91+Aohp91dk6bezefW7fL03s6D3MG4ZFgho=");

  it("decrypts login object", async () => {
    // initialize serialization:
    SharedBox;

    const sb: SharedBox = await fromBoss(sampleLoginObject);
    // console.log(sb);
    await sb.unlockWithKeys((await Credentials.deriveKeysFromPassword("qwert12345.")).loginAccessKey);
    // console.log(Boss.load(await sb.payloadPromise));
    const pk: PrivateKey = await fromBoss(await sb.payloadPromise, "loginKey");
    expect(pk.publicKey.longAddress.asString).toBe("b8biSMPEd7K1GvxXqUNDkcrScrNdLWDK236X5MLxuUP4qukrT4sKc36dh9NNXu8ZAhhSdn4M");
    // const pa = x.packedAccessors;
    // console.log(JSON.stringify(pa.keys, null, 2));
    // console.log(JSON.stringify(pa.values, null, 2));
  })

  it("Sbox create, pack, unpack", async() => {
    const key = await PrivateKey.generate({strength:2048});
    const sbKey1 = await AnnotatedKey.fromPassword("foo", "a", 100);
    const sbKey2 = AnnotatedKey.createRandomSymmetric();
    const sb = await SharedBox.createWith({
      foo: key,
      bar: 42
    });
    await sb.addKeys(sbKey1, sbKey2);
    const packed = await sb.pack();
    for(const k of [sbKey1,sbKey2]) {
      const sb2 = await SharedBox.unpack(packed);
      await sb2.unlockWithKeys(k);
      const result: { foo: PrivateKey, bar: number } = await sb2.deserialize();
      expect(result.bar).toBe(42);
      expect(result.foo.publicKey.longAddress.asString).toBe(key.publicKey.longAddress.asString);
    }
  })

  it("iterates over a map", () => {
    const x = new Map<string,number|string>();
    x.set("foo","bar");
    x.set("bar", 42);
    for( let [k,v] of x) {
      console.log(k,v);
    }
  })

})
