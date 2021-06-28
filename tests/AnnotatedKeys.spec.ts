import { AnnotatedKey, PasswordKeyAnnotation } from "../src/AnnotatedKey";
import { AnnotatedKeyring } from "../src/AnnotatedKeyring";
import { decode64, encode64Short, PrivateKey, randomBytes } from "unicrypto";
import { utf8ToBytes } from "uparsecjs";
import { PasswordKeyGenerator } from "../src/PasswordKeyGenerator";
import { MapSerializer } from "../src/MapSerializer";

describe('annotated keys', () => {

  it("keyring find by key", async () => {
    const salt = randomBytes(32);
    const passwordKey = await AnnotatedKey.fromPassword("foobar", salt, 150);
    const sk1 = AnnotatedKey.createRandomSymmetric();
    const sk2 = AnnotatedKey.createRandomSymmetric();
    const sk3 = AnnotatedKey.createRandomSymmetric();
    const pk1 = await AnnotatedKey.createPrivate(2048);
    const pk2 = await AnnotatedKey.createPrivate(2048);
    const psw1 = await AnnotatedKey.fromPassword("foo", "bar",100);

    const kr = new AnnotatedKeyring()
      .addKeys(sk1, sk2, sk3, passwordKey, pk1, pk2, psw1)
      .addPasswords("bad1", "bad2");

    for (const key of [sk1, sk2, sk3, passwordKey, pk1, pk2, psw1]) {
      const x = await kr.findKey(key.annotation);
      if (!x?.matchesAnnotation(key.annotation)) {
        fail("does not match annotation on " + JSON.stringify(key.annotation));
      }
      expect(await x.packedKey).toEqual(await key.packedKey)
    }
  })

  it("keyring find by password", async () => {
    const salt = randomBytes(32);
    const passwordKey = await AnnotatedKey.fromPassword("foobar", salt, 150);
    const sk1 = AnnotatedKey.createRandomSymmetric();
    const sk2 = AnnotatedKey.createRandomSymmetric();
    const sk3 = AnnotatedKey.createRandomSymmetric();

    const kr = new AnnotatedKeyring()
      .addKeys(sk1, sk2, sk3)
      .addPasswords("notgood", "foobar");

    // Password key was not added so it shouls regenerate from password kept in the ring
    const x = await kr.findKey(passwordKey.annotation);
    expect(x?.matchesAnnotation(passwordKey.annotation)).toBe(true)
    expect(await x?.packedKey).toEqual(await passwordKey.packedKey)
  })

  it("encrypts and decrypts", async () => {
    const plaintext = utf8ToBytes("foo bar bazz 42");
    const salt = randomBytes(47);
    const passwordKey = await AnnotatedKey.fromPassword("foo", salt, 100);
    const keys = [AnnotatedKey.createRandomSymmetric(),
      await AnnotatedKey.createPrivate(2048),
      passwordKey
    ];
    for (const k of keys) {
      expect(await k.etaDecrypt(await k.etaEncrypt(plaintext))).toEqual(plaintext);
    }
    const passwordKey2 = await PasswordKeyGenerator.restoreKey(
      "foo",
      passwordKey.annotation as PasswordKeyAnnotation
    );
    expect(await passwordKey2!.etaDecrypt(await passwordKey.etaEncrypt(plaintext))).toEqual(plaintext);
  });

  it("serializes keys", async () => {
    const ak1 = await AnnotatedKey.fromPassword("12345", "hehe", 100);
    const ak2 = await AnnotatedKey.createPrivate(2048)
    const ak3 = AnnotatedKey.createRandomSymmetric();
    for (const k of [ak1, ak2, ak3]) {
      const packed = await MapSerializer.toBoss(k);
      const ak1r = await MapSerializer.fromBoss<AnnotatedKey>(packed);
      expect(ak1r.matchesAnnotation(k.annotation));
      expect(await ak1r.packedKey).toEqual(await k.packedKey);
    }
  });

  it("cross-deserializes keyrings", async () => {
    const src = decode64(`
NzNhY2Nlc3MHCySDQW5ub3RhdGVkS2V5cmluZ0twYXNzd29yZHMXJRtTZXQjZGF0YRYbYmFy
G2ZvbyNrZXlzHxclg1JTQUtleUFubm90YXRpb24TaWS8NRAnnvSH5Ff81FzzyUc6nb2v7dK8
8YDexKVPC2c7Z/OgbnwI48o+fQEXyof39Hc8YB5Vbf20H1Nhbm5vdGF0aW9ufSVjQW5ub3Rh
dGVkS2V5G2tleRclU1ByaXZhdGVLZXkzcGFja2VkxAoBJgAcAQABvIDnijlnYWD18WrxyhjI
dQr7wa9STsjIbg12YsFBu/J1VMgRNCIML3XdNdsmHmegBkgc3Nxl7KVh4t3Q6kPMAcEfbVJq
1sXRuma/NLJ0e3jX6KgRwLxznKBPrlhQc4SxuM7l/nelZGvOXLllGFL2dIvqyFS2htO9YXUT
vD2NTjmbEbyA41HChTzwCwSsE614uB01auym09aElIyUA9Lk657Db5fFpNwS+/Q1+ohjG4iK
LUCUPf5yvGpU20juH4GRumC/YEf0PefQ9EfrShDkmF5l8qCdsmi7NuoKSjh2DIkTnjZJabm4
OVXEmceHh2SkDECXkRnkAfIHu85/S6Ub9HDOnc0XJbNTeW1tZXRyaWNLZXlBbm5vdGF0aW9u
jYT8lBIZNdmgCljROO5mUKpcH6W9GyWttRclY1N5bW1ldHJpY0tleb0ZvCA7QsbbroHybT19
s8JvnDaIlk5CEEMAXEZHcLNK4QMW20dLa2V5TGVuZ3RouCAjc2FsdExoZWxsb1NhbHQlq1Bh
c3N3b3JkS2V5QW5ub3RhdGlvbjNkaWdlc3QPI25hbWUzU0hBMjU2U2Z1bGxMZW5ndGi4QI28
IGncnB7KMt7/KEiZi6BtAmYRHoK0auYhLJXSRIi9azKJS2tleU9mZnNldAAzcm91bmRzKB+l
vSIlrbUXJb0gvRm8ILXczRrYtw5OF9vTqEDsdSYQH/JyC8UYDWr81B/IrJ62Y3Bhc3N3b3Jk
VGFncw9lFyVFTRY7Zm9vcGFzczNmb29wd2Q7a2V5VGFncx99FyVFTRYbUlNBu01hZGRyOko3
aG5TQ3I5QlFzSnNYNk5KcU05YTVibW92ajgzZEFuWmdxM2lZODZTeHlka29iVVh3Q2NaZTZp
TGNUZTl0a0Vnd2JkOTZGTb0bFyVFTRa7GWlkOi9KUVNHVFhab0FwWTBUanVabENxWEFLc3lt
bWV0cmljvSIXJUVNFrsuaWQ6YWR5Y0hzb3kzdjhvU0ptTG9HMENaaEVlZ3JScTVpRXNsZEpF
aUwxck1va1twYXNzd29yZEtleQ==`);
    const kr: AnnotatedKeyring = await MapSerializer.fromBoss(src);
    // console.log(kr.enumerateKeys())
    // console.log(kr.enumeratePasswords())
    const passwords = kr.allPasswords();
    expect(passwords.get("foo")).not.toBeNull();
    expect(passwords.get("foo")).toContain("foopass")
    expect(passwords.get("foo")).toContain("foopwd")
    expect(passwords.get("bar")).not.toBeNull();
    expect(passwords.get("bar")?.size).toBe(0);

    const keys = kr.allKeys();
    for( const k of keys) {
      console.log(`${k.key.annotationLabel} -> ${[...k.tags]} `)
    }
    const krsa = kr.taggedKey("RSA")!;
    let tag = `addr:${(krsa.key as PrivateKey).publicKey.longAddress.asString}`;
    expect(kr.tags(krsa)).toContain(tag);

    const ksymm = kr.taggedKey("symmetric")!;
    tag = `id:${encode64Short(ksymm!.annotation.id)}`;
    expect(kr.tags(ksymm)).toContain(tag);

    const kPassword = kr.taggedKey("passwordKey")!;
    tag = `id:${encode64Short(kPassword!.annotation.id)}`;
    expect(kr.tags(kPassword)).toContain(tag);
  });

  it("serializes keyrings", async () => {
    const salt = randomBytes(32);
    const passwordKey = await AnnotatedKey.fromPassword("foobar", salt, 150);
    const sk1 = AnnotatedKey.createRandomSymmetric();
    const sk2 = await AnnotatedKey.createPrivate(2048);

    const kr = new AnnotatedKeyring()
      .addKeys(sk1)
      .addTaggedKeys({ key: sk2, tags: ["sk2"] })
      .addPasswords("notgood", "foobar")
      .addTaggedPasswords({ password: "foo2", tags: ["secondFOO"] })

    // Password key was not added so it shouls regenerate from password kept in the ring
    const check = async (r: AnnotatedKeyring) => {
      const x = await r.findKey(passwordKey.annotation);
      expect(x?.matchesAnnotation(passwordKey.annotation)).toBe(true)
      expect(await x?.packedKey).toEqual(await passwordKey.packedKey)
      expect(await (r.keysByTag("sk2")[0]?.packedKey)).toEqual(await sk2.packedKey);
      expect(await(await r.findKey(sk2.annotation))?.packedKey).toEqual(await sk2.packedKey);
      // console.log((await r.findKey(sk1.annotation))?.packedKey);
      expect(await(await r.findKey(sk1.annotation))?.packedKey).toEqual(await sk1.packedKey);
      expect(await(await r.findKey(sk1.annotation))?.packedKey).not.toEqual(await sk2.packedKey);
      const pkx = await r.findKey(passwordKey.annotation);
      expect(await pkx?.packedKey).toEqual(await passwordKey.packedKey);
    }
    await check(kr);
    const packed = await kr.toMap();
    const kr2 = await MapSerializer.deserialize<AnnotatedKeyring>(packed);
    await check(kr2);
  });

})
