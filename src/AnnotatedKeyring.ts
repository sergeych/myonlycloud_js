import {
  AnnotatedKey,
  annotationLabel,
  deserializeKeyAnnotation,
  KeyAnnotation,
  serializeKeyAnnotation
} from "./AnnotatedKey";
import { PasswordKeyGenerator } from "./PasswordKeyGenerator";
import { BossObject } from "uparsecjs";
import { MapSerializer, Serializable, SerializedSet } from "./MapSerializer";
import { isEmptyObjectOrMap } from "./tools";

@Serializable
export class AnnotatedKeyring {
  private readonly keys = new Map<string, AnnotatedKey>();
  private readonly passwords = new Set<string>();
  private readonly passwordTags = new Map<string, Set<string>>();
  private readonly keyTags = new Map<string, Set<string>>();

  static Exception = class extends Error {
  };
  static TooManyKeysException = class extends AnnotatedKey.Exception {
  };

  constructor(...keys: AnnotatedKey[]) {
    this.addKeys(...keys);
  }

  clone(): AnnotatedKeyring {
    return new AnnotatedKeyring().mergeWith(this);
  }

  addKeys(...keys: AnnotatedKey[]): AnnotatedKeyring {
    for (const k of keys) this.keys.set(k.annotationLabel, k);
    return this;
  }

  addTaggedKeys(...tks: { key: AnnotatedKey; tags?: string[] }[]): AnnotatedKeyring {
    for (const tk of tks) {
      const label = tk.key.annotationLabel;
      this.keys.set(label, tk.key);
      if (tk.tags) {
        for (const t of tk.tags) {
          let set = this.keyTags.get(t);
          if (!set) {
            set = new Set<string>();
            this.keyTags.set(t, set);
          }
          set.add(label);
        }
      }
    }
    return this;
  }

  tags(source: AnnotatedKey | KeyAnnotation | string): Set<string> {
    if (typeof (source) === 'string')
      return new Set(this.passwordTags.get(source) ?? []);
    const label = source instanceof AnnotatedKey ? source.annotationLabel : annotationLabel(source);
    const result = new Set<string>();
    for (const [tag, labels] of this.keyTags) {
      if (labels.has(label)) result.add(tag);
    }
    return result;
  }

  allKeys(): { key: AnnotatedKey; tags: Set<string> }[] {
    return [...this.keys.values()].map(key => {
      return { key, tags: this.tags(key) };
    });
  }

  allPasswords(): Map<string, Set<string>> {
    const result = new Map();
    for (const password of this.passwords) {
      result.set(password, this.tags(password));
    }
    return result;
  }

  addTaggedPasswords(...passwords: { password: string; tags?: string[] }[]): AnnotatedKeyring {
    for (const x of passwords) {
      this.passwords.add(x.password);
      if (x.tags) {
        for (const t of x.tags) {
          let set = this.passwordTags.get(x.password);
          if (!set) {
            set = new Set<string>();
            this.passwordTags.set(x.password, set);
          }
          set.add(t)
        }
      }
    }
    return this;
  }

  addPasswords(...passwords: string[]): AnnotatedKeyring {
    for (const password of passwords) this.addTaggedPasswords({ password });
    return this;
  }

  /**
   * Find the key in the ring that matches annotation. It checks all keys and all passwords in the ring,
   * so it could be slow. Returns only _the first key/password that matches_.
   * @param annotations that our key must match
   */
  async findKey(...annotations: KeyAnnotation[]): Promise<AnnotatedKey | undefined> {
    // first check only against stored keys as password checks is really slow
    for (const a of annotations) {
      const key = this.keys.get(annotationLabel(a));
      if (key) return key;
      // also, there could be matching keys with different labels
      for( const key of this.keys.values()) {
        if( key.matchesAnnotation(a))
          return key;
      }
    }

    // there was no key, try passwords
    for (const a of annotations) {
      if (a.type == "PasswordKeyAnnotation") {
        for (const password of this.passwords) {
          const key = await PasswordKeyGenerator.restoreKey(password, a);
          if (key) {
            this.addKeys(key);
            return key;
          }
        }
      }
    }
    return undefined;
  }

  keysByTag(...tags: string[]): AnnotatedKey[] {
    const result = Array<AnnotatedKey>();
    for (const tag of tags) {
      const labels = this.keyTags.get(tag);
      if (labels) {
        for (const l of labels) {
          const key = this.keys.get(l);
          if (key) result.push(key);
        }
      }
    }
    return result;
  }

  /**
   * Retrieve a single key by a tag or undefined. If there are more than one key with such tag, throws exception.
   * Use {@link keysByTag} to retrieve several keys, or any of them.
   * @param tag to look for
   * @return matched key or undefined
   * @throws AnnotatedKeyring.TooManyKeysException if there are more than one matching keys.
   */
  taggedKey(tag: string): AnnotatedKey | undefined {
    const result = this.keysByTag(tag);
    switch (result.length) {
      case 0:
        return undefined;
      case 1:
        return result[0];
      default:
        throw new AnnotatedKeyring.TooManyKeysException(`expected 1 key for tag [${tag}], got ${result.length}`);
    }
  }

  addTagsTo(item: KeyAnnotation | AnnotatedKey | string, ...tags: string[]): AnnotatedKeyring {
    if (typeof (item) === 'string') {
      return this.addTagsToPassword(item, ...tags);
    }
    const label = item instanceof AnnotatedKey ? item.annotationLabel : annotationLabel(item);
    if (!this.keys.get(label))
      throw new Error("can't tag: key not exists")
    for (const tag of tags) {
      let existing = this.keyTags.get(tag);
      if (!existing) {
        existing = new Set<string>();
        this.keyTags.set(tag, existing);
      }
      existing.add(label);
    }
    return this;
  }

  addTagsToPassword(password: string, ...tags: string[]): AnnotatedKeyring {
    if (!this.passwords.has(password))
      throw new Error("can't tag: password not found")
    let existing = this.passwordTags.get(password);
    if (!existing) {
      existing = new Set();
      this.passwordTags.set(password, existing);
    }
    for (const tag of tags)
      existing.add(tag);
    return this;
  }

  mergeWith(other: AnnotatedKeyring): AnnotatedKeyring {
    for (const kt of other.allKeys()) {
      this.addTaggedKeys({ key: kt.key, tags: [...kt.tags] })
    }
    for(const [password, tags] of other.allPasswords()) {
      this.addTaggedPasswords({password,tags: [...tags]})
    }
    return this;
  }

  async toMap(): Promise<BossObject> {
    const keys = new Map<BossObject, BossObject>();
    const keyTags = new Map<BossObject, BossObject>();
    for (const k of this.keys.values()) {
      const serializedAnnotation = serializeKeyAnnotation(k.annotation);
      keys.set(serializedAnnotation, await k.toMap());
      const tags = Array<string>();
      for (const [tag, labels] of this.keyTags) {
        if (labels.has(k.annotationLabel))
          tags.push(tag);
      }
      if (tags.length > 0) {
        keyTags.set(serializedAnnotation, { $: 'Set', data: [...tags] });
      }
    }
    const passwordTags = new Map<string, BossObject>();
    for (const [password, tags] of this.passwordTags) {
      // passwordTags.set(password, {$:'Set',data: [...tags.values()]});
      passwordTags.set(password, await MapSerializer.serialize(tags) as BossObject);
    }
    return {
      $: "AnnotatedKeyring",
      keys,
      passwords: await MapSerializer.serialize(this.passwords),
      passwordTags,
      keyTags
    };
  }

  static async fromMap(source: BossObject): Promise<AnnotatedKeyring> {
    /*
        private val keys: MutableMap<KeyAnnotation, AnnotatedKey> = HashMap(),
        private val passwords: MutableSet<String> = HashSet(),
        private val passwordTags: MutableMap<String, MutableSet<String>> = HashMap(),
        private val keyTags: MutableMap<KeyAnnotation, MutableSet<String>> = HashMap(),

     */
    // JS does not work anyway well with object-keyed maps so we must recreate:
    const keys: AnnotatedKey[] = []
    for (const [, packedKey] of (source.keys as Map<BossObject, BossObject>))
      keys.push(await MapSerializer.deserialize(packedKey));

    const result = new AnnotatedKeyring(...keys);

    // keyTags now contain a serialized set, e.g. {$:'Set',data: stirng[]}
    if( !isEmptyObjectOrMap(source.keyTags)) {
      const keyTagsMap = source.keyTags as Map<BossObject, SerializedSet<string>>;

      for (const [k, v] of keyTagsMap) {
        const annotation = deserializeKeyAnnotation(k);
        result.addTagsTo(annotation, ...v.data);
      }
    }
    const passwords = source.passwords as SerializedSet<string>;
    result.addPasswords(...passwords.data);
    const passwordTagMap = source.passwordTags as Record<string, SerializedSet<string>>;
    for (const password in passwordTagMap) {
      // its just the fucking javascript
      if (Object.prototype.hasOwnProperty.call(passwordTagMap, password)) {
        result.addTagsTo(password, ...passwordTagMap[password].data);
      }
    }
    return result;
  }

}
