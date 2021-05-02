export function trimToSize(source: string|null|undefined,size: number): string {
  if( !source) return "";
  if( source.length <= size ) return source;
  return source.substr(0, size-1) + "…";
}

