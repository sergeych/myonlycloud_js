/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-use-before-define */
import { BossObject, BossPrimitive } from "uparsecjs";
import { Boss, KeyAddress, PrivateKey, PublicKey, SymmetricKey } from "unicrypto";

interface MapSerializationHandler<T> {
  serialize: (instance: T) => Promise<BossObject>;
  deserialize: (map: BossObject) => Promise<T>;
}

/**
 * The simple object that has sort of "copy constructor" that assigns all properties from an argument.
 * Useful to implement interfaces.
 */
export class CaseObject {
  constructor(props: any) {
    Object.assign(this, props)
  }
}

export interface MapSerializable {
  toMap(): Promise<BossObject>;
}

interface MapDeserializable<T> extends Function {
  fromMap(params: BossObject): Promise<T>;
}

const handlers = new Map<string, MapSerializationHandler<any>>();

// noinspection JSUnusedGlobalSymbols
export class MapSerializer {

  static Exception = class extends Error {
  }

  static NotFound = class extends MapSerializer.Exception {
  }

  static registerClass<T extends MapSerializable>(cls: MapDeserializable<T>, overrideName?: string): void {
    const name = overrideName ?? cls.prototype.constructor.name;
    if (!name) throw Error("MapSerialization can't derive name from " + cls);
    handlers.set(name, {
      deserialize: map => cls.fromMap(map),
      serialize: instance => instance.toMap()
    })
  }

  static registerCaseObject<T extends { new(props: any): CaseObject }>(cls: T, overrideName?: string): void {
    const name = cls.prototype.constructor.name;
    if (!name) throw Error("MapSerialization can't derive name from " + cls);
    const h = {
      deserialize: async (src: BossObject) => {
        const props = await deserializeMap(src);
        delete props.$;
        return new cls(props);
      },
      serialize: async (instance: any) => {
        return { ...await serializeMap(instance), $: overrideName ?? name };
      }
    };
    handlers.set(name, h);
    if( overrideName ) handlers.set(overrideName, h);
  }

  static register<T>(name: string, handler: MapSerializationHandler<T>): void {
    handlers.set(name, handler);
  }

  static async deserialize<T>(serialized: BossObject): Promise<T> {
    if (!serialized.$)
      throw new MapSerializer.Exception("missing type parameter ($)");
    if (typeof (serialized.$) != "string")
      throw new MapSerializer.Exception("MapSerializer type parameter is not a string: " + serialized.$);
    const handler = handlers.get(serialized.$);
    if (handler == undefined)
      throw new MapSerializer.Exception("MapSerializer unknown type: " + serialized.$);
    return handler.deserialize(serialized);
  }

  static async serializeAny(source: any): Promise<BossPrimitive> {
    switch (typeof source) {
      case "undefined":
        return null;
      case "object":
        if (source instanceof Array) {
          const result: BossPrimitive[] = [];
          for (const item of source) result.push(await this.deserializeAny(item));
          return result;
        }
        if (source instanceof Map) return serializeMap(source);
        return MapSerializer.serialize(source);
      case "boolean":
      case "number":
      case "string":
        return source;
      case "function":
        break;
      case "symbol":
        break;
      case "bigint":
        break;
    }
    throw new MapSerializer.Exception("can't serialize: " + source);
  }

  static async deserializeAny(source: BossPrimitive): Promise<any> {
    switch (typeof (source)) {
      case "undefined":
        return undefined;
      case "object": {
        if (source == null || source instanceof Uint8Array) return source;

        if (source instanceof Array) {
          const result = Array<any>();
          for (const x of source) result.push(await this.deserializeAny(x));
          return result;
        }

        // if( source instanceof Map )
        //   throw new Error("map deserializing not yet implemented");

        // object, convert field values:
        const result: Record<string, unknown> = {};
        const obj = source as BossObject;
        // typed object?
        if (obj.$)
          return await this.deserialize(obj)

        // not typed - just an object (like map)
        for (const field in obj) {
          if (!Object.prototype.hasOwnProperty.call(obj, field)) continue;
          result[field] = await this.deserializeAny(obj[field]);
        }
        return result;
      }
      case "boolean":
      case "number":
      case "string":
      case "bigint":
        return source;
      case "function":
      case "symbol":
        throw new MapSerializer.Exception(`this type ${typeof (source)} could not be in deserializing data`);
    }
    throw new Error("this should not happen");
  }

  /**
   *
   * @param source
   */
  static async serialize(source: any): Promise<BossObject | BossPrimitive> {
    let result: BossObject | undefined;
    const typeName = source.constructor.name;
    if (typeof (source.toMap) == 'function')
      result = await source.toMap();
    else if(source instanceof  Uint8Array) {
      return source;
    }
    else {
      const handler = handlers.get(source.constructor.name);
      // console.log("handlers:", handlers);
      // console.log("handler keys:", handlers.keys());
      // console.log("source: ",source,"handler:",handler);
      if (!handler)
        result = await serializeMap(source)
        // throw new MapSerializer.Exception("MapSerializer: dont' know how to serialize: " + source.constructor.name);
      else
        result = await handler.serialize(source);
    }
    if (!result)
      throw new MapSerializer.Exception("don't know how to serialize " + source);
    if (!result.$ && typeName != 'Object') result.$ = typeName;
    return result;
  }

  static async toBoss(source: any): Promise<Uint8Array> {
    return Boss.dump(await this.serializeAny(source));
  }

  /**
   * Unpack boss binary and deserialize its root object or object at some path.
   * @param packed binary boss-packed data
   * @param path if present, specify the path inside unpacked data to the object to unpack.
   * @return promise to the unpacked object.
   * @throws NotFound if path does not existing in the unpacked object
   * @throws Exception if deserialization failed
   */
  static deserializeBoss<T>(allowNotTyped = false, packed: Uint8Array, ...path: string[]): Promise<T> {
    let unpacked;
    try {
      unpacked = Boss.load(packed);
    } catch {
      // this means binary data are corrupt or not in a BOSS format:
      throw new MapSerializer.Exception("wrong BOSS packed data");
    }
    while (path.length > 0 && unpacked != undefined) {
      const field = path.shift();
      unpacked = field ? unpacked[field] as BossObject : undefined;
    }
    if (!unpacked)
      throw new MapSerializer.Exception("path not found: " + path.join("."));
    return allowNotTyped ? this.deserializeAny(unpacked) : this.deserialize(unpacked);
  }

  static fromBoss<T>(packed: Uint8Array, ...path: string[]): Promise<T> {
    return this.deserializeBoss(false, packed, ...path);
  }

  static anyFromBoss<T>(packed: Uint8Array, ...path: string[]): Promise<T> {
    return this.deserializeBoss(true, packed, ...path);
  }
}


/**
 * Convert all elements of a Record type object.
 * Very specific case: deserialize a map ignoring its type tag. Used to deserialize
 * [[CaseObject]] like classes.
 * @param map to concert.
 */
async function deserializeMap(map: BossObject): Promise<Record<string, any>> {
  const result: Record<string, any> = {};
  for (const key in map) {
    if (!Object.prototype.hasOwnProperty.call(map, key)) continue;
    result[key] = await MapSerializer.deserializeAny(map[key]);
  }
  return result;
}

async function serializeMap<T extends Record<string, any>>(source: T): Promise<BossObject> {
  const result: BossObject = {};
  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    result[key] = await MapSerializer.serializeAny(source[key]);
  }
  return result;
}


/**
 * Decorator to register a class as MapSerializable providing it meets interface requirements. Works only
 * if the class constructor name is the same as a type tag. If not, use direct registration with
 * [[MapSerializer.registerClass]] for example.
 * @param cls class to register
 */
export function Serializable(cls: MapDeserializable<MapSerializable>) {
  MapSerializer.registerClass(cls);
}

export function fromBoss<T>(packed: Uint8Array, ...path: string[]): Promise<T> {
  return MapSerializer.fromBoss(packed, ...path);
}

// noinspection JSUnusedGlobalSymbols
export function toBoss(source: Function | MapSerializable): Promise<Uint8Array> {
  return MapSerializer.toBoss(source);
}

MapSerializer.register("PrivateKey", {
  async serialize(key: PrivateKey) {
    return { packed: await key.pack() };
  },
  async deserialize(source: BossObject) {
    return await PrivateKey.unpack(source.packed as Uint8Array);
  }
});

MapSerializer.register("PublicKey", {
  async serialize(key: PublicKey) {
    return { packed: await key.pack() };
  },
  async deserialize(source: BossObject) {
    return await PublicKey.unpack(source.packed as Uint8Array);
  }
});

MapSerializer.register("SymmetricKey", {
  async serialize(key: SymmetricKey) {
    return { packed: key.pack() };
  },
  async deserialize(source: BossObject) {
    return new SymmetricKey({ keyBytes: source.packed as Uint8Array });
  }
});

MapSerializer.register("KeyAddress", {
  async serialize(keyAddress: KeyAddress) {
    return { packed: keyAddress.bytes };
  },
  async deserialize(source: BossObject) {
    return new KeyAddress(source.packed as Uint8Array);
  }
});

MapSerializer.register<Date>("Date", {
  deserialize(map: BossObject): Promise<Date> {
    const t = map.unixtimeMillis;
    if( !t || typeof (t) != 'number') throw new Error("serialized date has no proper unixtimeMillis field");
    return Promise.resolve(new Date(t));
  }, serialize(instance: Date): Promise<BossObject> {
    return Promise.resolve({unixtimeMillis: instance.getTime()});
  }

});

export type SerializedSet<T> = {
  $: 'Set';
  data: T[];
}

MapSerializer.register<Set<any>>("Set", {
  async deserialize(map: BossObject): Promise<Set<any>> {
    const source = map as SerializedSet<any>;
    return new Set(source.data.map(x => MapSerializer.deserializeAny(x)));
  },
  async serialize(instance: Set<any>): Promise<BossObject> {
    return {
      $: 'Set',
      data: [...instance.values()]
    };
  }
})

