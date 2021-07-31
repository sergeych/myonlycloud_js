import { CaseObject, MapSerializer } from "../src/MapSerializer";
import { BossObject, BossPrimitive } from "uparsecjs";

describe('map serialization', () => {

  it("test JS maps", () => {
    type KT = { foo: string; value: number };
    const m1 = new Map<KT, string>();

    const k1 = { foo: "bar", value: 41 };
    const k2 = { foo: "bar", value: 43 };
    const k11 = { foo: "bar", value: 41 };

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
    }

    MapSerializer.registerCaseObject(T1);

    const t1 = new T1({foo: "bar", bar: 42, date: new Date()});
    expect(t1.foo).toEqual("bar");
    expect(t1.bar).toEqual(42);

    const st = await MapSerializer.serialize(t1) as any;
    console.log(st);
    expect(st?.$).toEqual("T1");
    const t2 = await MapSerializer.deserialize<T1>(await MapSerializer.serialize(t1) as BossObject);
    console.log(t2);
    expect(t2.foo).toEqual("bar");
    expect(t2.bar).toEqual(42);
  });

})
