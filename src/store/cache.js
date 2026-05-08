import { LRUCache } from "lru-cache";

const cache = new LRUCache({
  max: 1000,
  ttl: 1000 * 60 * 10,
});

export function getCache(key) {
  return cache.get(key);
}

export function setCache(key, value) {
  cache.set(key, value);
}

export function clearCache() {
  cache.clear();
}
