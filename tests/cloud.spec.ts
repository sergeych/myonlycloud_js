import { MyoCloud } from "../src/MyoCloud";
import { MemorySessionStorage } from "uparsecjs/dist/MemorySessionStorage";
import { Config } from "../src/Config";
import { PrivateKey } from "unicrypto";
import { AnnotatedKey } from "../src/AnnotatedKey";
import { RemoteException, RootConnection, Session, timeout } from "uparsecjs";

describe('cloudservice', () => {

  function createSession(useLocal=false) {
    const serviceAddress = useLocal ? "http://localhost:8094/api/p1" : "https://api.myonly.cloud/api/p1";
    return new MyoCloud(new MemorySessionStorage(), {
      serviceAddress, testMode: true
    });
  }



  it("login with no session", async () => {
    jest.setTimeout(15_000)
    const cloud = new MyoCloud(new MemorySessionStorage(), {
      serviceAddress: "http://localhost:8094/api/p1", testMode: true
    });
    expect(cloud.isLoggedIn).toBeUndefined();
    expect(cloud.hasSavedLogin).toBe(false);
    console.log("pre conn");
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
    jest.setTimeout(15000);
    const s = createSession(false);
    Config.testMode = false
    await s.login("test_21", "qwert12345.");
    try {
      for await (const ib of s.inboxes()) {
        console.log(`inbox: ${ib.name}: ${ib.id}`)
      }
      //no such method
      console.log(await s.call("check"));
      //console.log(await s.call("sessionGetInfo"));
      console.log("done")
    }
    catch(e) {
      console.log("strange failure", e);
      throw e;
    }
  })

  it("registers", async() => {
    jest.setTimeout(95000)
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
  });

  it("handles properly invalid session connections", async() => {
    const rc = new RootConnection("http://localhost:9876/api/p1");
    try {
      const res = await rc.call("check");
      fail("it should throw exception");
    }
    catch(e) {
    }

    const session = new Session(
      new MemorySessionStorage(),
      rc,
      (r) => Promise.resolve([]),
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



  it("ready for obejct loading", async() => {
    // const aa : Record<string,number> = {
    //   kk: 1,
    //   ll: 3
    // };
    // for( const x in ownKeys(aa)) {
    //   console.log(">> "+x+" -> "+aa[x]);
    // }
  })

})
