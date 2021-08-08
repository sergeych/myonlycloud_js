import { CaseObject, MapSerializer } from "../src";
import { MemorySessionStorage } from "uparsecjs/dist/MemorySessionStorage";
import { randomBytes } from "unicrypto";
import { SessionValue } from "../src/SessionValue";

describe('map serialization', () => {

  it("test JS maps", () => {
    type KT = { foo: string; value: number };
    const m1 = new Map<KT, string>();

    const k1 = { foo: "bar", value: 41 };
    const k2 = { foo: "bar", value: 43 };

    m1.set(k1, "k1");
    m1.set(k2, "k2");

    expect(m1.get(k1)).toEqual("k1");
    expect(m1.get(k2)).toEqual("k2");
    //expect(m1.get(k11)).toEqual("k1"); // fails because js can't compare object as keys
  });

  it("serializes simple structures properly", async () => {
    type KT = { foo: string; value: number };
    const x: KT = { foo: "123", value: 42};
    const x2 = await MapSerializer.deserializeAny(await MapSerializer.serializeAny(x));
    expect(x2).toEqual(x);
  })

  it("serializes case classes", async () => {
    class T1 extends CaseObject {
      foo!: string;
      bar!: number;
      date: Date;
      optString?: string;
    }

    MapSerializer.registerCaseObject(T1);

    const d = new Date();
    const t1 = new T1({foo: "bar", bar: 42, date: d});
    expect(t1.foo).toEqual("bar");
    expect(t1.bar).toEqual(42);


    const st = await MapSerializer.serialize(t1) as any;
    console.log(st);
    expect(st?.$).toEqual("T1");
    const t2 = await MapSerializer.fromBoss<T1>(await MapSerializer.toBoss(t1));
    console.log(t2);
    expect(t2.foo).toEqual("bar");
    expect(t2.bar).toEqual(42);
    expect(t2.optString).toBeUndefined();
    expect(t2.date.getTime()).toBeCloseTo(d.getTime());
  });

  it("serializes undefineds", async() => {
    class T2 {

      cloudId?: number;
      title?: string;
      value: number;

      constructor(props: Partial<T2>) {
        Object.assign(this,props);
      }
    }

    MapSerializer.registerCaseObject(T2);
    const t1: T2 = new T2({value: 42, title: undefined});
    const t2 = await MapSerializer.anyFromBoss<T2>(await MapSerializer.toBoss(t1));
    // console.log(t1);
    // console.log(t2);
    expect(t2.value).toBe(42);
    expect(t2.cloudId).toBeUndefined();
    expect(t2.title).toBeUndefined();
  });

  it("supports session value",() => {
    const ms = new MemorySessionStorage();
    const data = randomBytes(32);
    const v1 = new SessionValue(ms, "v1");
    v1.value = data;
    expect(v1.value).toEqual(data);
    const v2 = new SessionValue(ms, "v1");
    expect(v2.value).toEqual(data);
  });

})
