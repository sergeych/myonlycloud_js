export type Tags = { uniqueTag?: string; tag1?: string; tag2?: string; tag3?: string }
export type LO = { limit?: number; offset?: number };

export interface CloudElement extends Tags {
  id?: number;
  serial?: number;
  revision?: number;
  createdAt?: Date;
  updatedAt?: Date;
  head?: Uint8Array;
}

