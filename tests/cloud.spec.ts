import { AnnotatedKey, CloudElement, Config, MapSerializer, MyoCloud, RegistryData } from "../src";
import { MemorySessionStorage } from "uparsecjs/dist/MemorySessionStorage";
import { PrivateKey } from "unicrypto";
import { RootConnection, Session, utf8ToBytes } from "uparsecjs";

function getServiceAddress(useLocal: boolean=false): string {
  return useLocal ? "http://localhost:8094/api/p1" : "https://api.myonly.cloud/api/p1";
}

describe('cloudservice', () => {

  jest.setTimeout(15_000)

  function createSession(useLocal=false) {
    const serviceAddress = getServiceAddress(useLocal);
    return new MyoCloud(new MemorySessionStorage(), {
      serviceAddress, testMode: true
    });
  }

  function createSessionAndStorage(useLocal=false) {
    const serviceAddress = getServiceAddress(useLocal);
    let storage = new MemorySessionStorage();
    return {
      session: new MyoCloud(storage, {
        serviceAddress, testMode: true
      }),
      storage
    }
  }

  it("login with no session", async () => {
    jest.setTimeout(15_000)
    const cloud = new MyoCloud(new MemorySessionStorage(), {
      serviceAddress: getServiceAddress(), testMode: true
    });
    expect(cloud.isLoggedIn).toBeUndefined();
    expect(cloud.hasSavedLogin).toBe(false);
    // console.log("pre conn");
    // await timeout(1000);
    await cloud.connected;
    expect(cloud.isLoggedIn).toBe(false);
    // try {
    //   console.log(await cloud.call("check"));
    //   fail("should throw");
    // }
    // catch(e){
    //   if( !(e instanceof RemoteException) || e.code != "parsec_not_signed_in")
    //     fail("invalid exception (expected not signed in): "+e);
    // }
  })

  it("logs in", async () => {
    jest.setTimeout(20000);
    const s = createSession(false);
    Config.testMode = false
    // await s.login("notest_1", "12345qwert!");
    await s.login("test_21", "qwert12345.");
    try {
      for await (const ib of s.inboxes()) {
        console.log(`inbox: ${ib.name}: ${ib.id}`)
      }
      //no such method
      console.log(await s.call("check"));
      //console.log(await s.call("sessionGetInfo"));
      const x = await s.scramble("foobar");
      console.log("scrambled:"+x);
      expect(x).not.toEqual("foobar");

      console.log("done")
    }
    catch(e) {
      console.log("strange failure", e);
      throw e;
    }
  });

  it("restores logged in session from storage", async() => {
    jest.setTimeout(20000);
    const {storage, session} = createSessionAndStorage(false);
    Config.testMode = true;
    // await s.login("notest_1", "12345qwert!");
    await session.login("test_21", "qwert12345.");
    const x1 = await session.scramble("foobar")
    const ss = new MyoCloud(storage, {
      serviceAddress: getServiceAddress(false), testMode: true
    });
    expect(await ss.checkConnection()).toBe("loggedIn");
    const x2 = await ss.scramble("foobar");
    expect(x2).toBe(x1);
  });

  /*
   * Explanation. Older account use different encryption scheme that is not yet implemented in this library
   * and may not be at all as there seems to be no account of concern of this type
   */
  // it("access old accounts", async () => {
  //   jest.setTimeout(15000);
  //   const s = createSession(false);
  //   Config.testMode = false
  //   const data = JSON.parse(fs.readFileSync("/Users/sergeych/.testdata/mctestdata.json").toString())
  //   const acc = data.oldAccount;
  //   console.log(acc.login);
  //   await s.login(acc.login, acc.password);
  //   console.log("well well");
  //   // await s.login("test_21", "qwert12345.");
  // //
  // })

  it("serializes registry", async() => {
    const k = await AnnotatedKey.createPrivate(2048);
    const rd = RegistryData.createNew(k);
    console.log(await MapSerializer.serialize(rd));
    const rd2 = await MapSerializer.fromBoss<RegistryData>(await MapSerializer.toBoss(rd));
    console.log(rd2);
    expect(rd2.source.storageKey.annotationLabel).toEqual(rd.source.storageKey.annotationLabel);
    expect(rd.source.keyring.findKey(k.annotation)).not.toBeUndefined()
  });

  it("handles properly invalid session connections", async() => {
    const rc = new RootConnection("http://localhost:9876/api/p1");
    try {
      await rc.call("check");
      fail("it should throw exception");
    }
    catch(e) {
    }

    const session = new Session(
      new MemorySessionStorage(),
      rc,
      () => Promise.resolve([]),
      true,
      2048
    );
    try {
      const res = await session.call("check");
      console.log(res);
      fail("it must throw exception");
    }
    catch(e) {
      console.log(e);
    }
  });

  it("creates element by id if not exists", async () => {
    const s = createSession(false);
    Config.testMode = false
    await s.login("test_21", "qwert12345.");
    const testData = utf8ToBytes("Welcome, cloud");
    const utag = "theCreationTestTag";
    const src: CloudElement = {
      uniqueTag: utag,
      head: testData
    };
    await s.deleteByUniqueTag(utag);
    let element = await s.tryCreateElement(src);
    console.log(element);
    expect(element).not.toBeNull();
    if( !element ) fail()
    expect(element?.uniqueTag).toBe(utag);
    expect(element?.head).toEqual(testData);

    let result = await s.tryCreateElement(src);
    expect(result).toBeUndefined();

    element.tag1 = "42"
    await s.updateElement(element);

    const element1 = await s.elementByUniqueTag(element.uniqueTag!);
    expect(element1?.tag1).toBe(element.tag1)

    s.deleteElements(element1!);

  });

  it("sets by unique tag", async () => {
    const s = createSession(false);
    Config.testMode = true;
    await s.login("test_21", "qwert12345.");
    const testData = utf8ToBytes("Welcome, cloud77");

    const e1: CloudElement = {
      uniqueTag: "creationTestTag",
      tag1: "tag-1",
      tag2: "tag-2",
      tag3: "tag-3",
      head: testData
    };

    await s.deleteByUniqueTag(e1.uniqueTag!);
    let e2 = await s.setByUniqueTag(e1);
    expect(e2.uniqueTag).toEqual(e1.uniqueTag);
    expect(e2.tag1).toEqual(e1.tag1);
    expect(e2.tag2).toEqual(e1.tag2);
    expect(e2.tag3).toEqual(e1.tag3);
    expect(e2.head).toEqual(e1.head);

    e1.tag3 = undefined;
    e1.tag1 = "supper tag";
    e2 = await s.setByUniqueTag(e1);
    expect(e2.uniqueTag).toEqual(e1.uniqueTag);
    expect(e2.tag1).toEqual(e1.tag1);
    expect(e2.tag2).toEqual(e1.tag2);
    expect(e2.tag3).toEqual(e1.tag3);
    expect(e2.head).toEqual(e1.head);

  });

  it("searches by tag", async () => {
    const s = createSession(false);
    Config.testMode = true;
    await s.login("test_21", "qwert12345.");
    const testData = utf8ToBytes("Welcome, cloud77");

    const e1: CloudElement = await s.setByUniqueTag({
      uniqueTag: "creationTestTag",
      tag1: "tag-1",
      tag2: "tag-2",
      tag3: "tag-3",
      head: testData
    });

    await s.setByUniqueTag({
      uniqueTag: "creationTestTag2",
      tag1: "tag-1",
      tag2: "tag-21",
      tag3: "tag-3",
      head: testData
    });

    let tt = await s.elementsByTags({tag1: "tag-1", afterSerial: 0});
    expect(tt.map(x=>x.tag2)).toEqual(["tag-2", "tag-21"]);

    tt = await s.elementsByTags({tag1: "tag-1", afterSerial: e1.serial});
    expect(tt.map(x=>x.tag2)).toEqual(["tag-21"]);
    expect(tt.length).toBe(1);

    tt = await s.elementsByTags({tag2: "tag-21"});
    expect(tt.map(x=>x.tag2)).toEqual(["tag-21"]);
    expect(tt.length).toBe(1);

  });



  it("registers", async() => {
    jest.setTimeout(35000)
    const s: MyoCloud = createSession(false)
    Config.testMode = true
    await s.connected
    expect(s.isLoggedIn).toBeFalsy()
    const k = await AnnotatedKey.createPrivate(2048);
    expect(
      await s.register("test21", "bar", k.key as PrivateKey)
    ).toBe("login_in_use");

    await s.clearTestLogin("..foobar");
    const result = await s.register("..foobar", "123123", k.key as PrivateKey);
    expect(result).toBe("OK");
    console.log("----------------------------------------------------- registration -------")
    await s.login("..foobar", "123123");
    expect(await s.checkConnection()).toBe("loggedIn");
  });



  // it("run tools", async() => {
  //   const part1 = Passwords.randomId(49);
  //   const part2 = Passwords.randomId(37);
  //   const part3 = Passwords.randomId(117);
  //   console.log(part1,part2,part3);
  //   // const aa : Record<string,number> = {
  //   //   kk: 1,
  //   //   ll: 3
  //   // };
  //   // for( const x in ownKeys(aa)) {
  //   //   console.log(">> "+x+" -> "+aa[x]);
  //   // }
  // });

});
