export class ExpiringValue<T> {
  #cachedValue?: T;
  #expiresAt!: number;

  constructor(value: T|undefined = undefined, expirationSeconds=0) {
    this.reset(value,expirationSeconds);
  }

  reset(value?: T,expirationSeconds = 0) {
    this.#cachedValue = value;
    this.#expiresAt = Date.now() + expirationSeconds*1000;
  }

  get value(): T | undefined {
    if( this.#cachedValue && Date.now() > this.#expiresAt ) {
      this.#cachedValue = undefined;
    }
    return this.#cachedValue;
  }

  clear() {
    this.#cachedValue = undefined;
  }
}