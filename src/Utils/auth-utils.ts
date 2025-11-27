import { randomBytes } from "crypto";
import NodeCache from "node-cache";
import type { Logger } from "pino";
import type {
  AuthenticationCreds,
  SignalDataSet,
  SignalDataTypeMap,
  SignalKeyStore,
  SignalKeyStoreWithTransaction,
  TransactionCapabilityOptions
} from "../Types";
import { Curve, signedKeyPair } from "./crypto";
import { delay, generateRegistrationId } from "./generics";
import { DEFAULT_CACHE_TTLS } from "../Defaults";
import { LRUCache } from "lru-cache";
import { Mutex } from "async-mutex";

/**
 * Adds caching capability to a SignalKeyStore
 * @param store the store to add caching to
 * @param logger to log trace events
 * @param opts NodeCache options
 */
export function makeCacheableSignalKeyStore(
  store: SignalKeyStore,
  logger: Logger,
  _cache?: NodeCache
): SignalKeyStore {
  const cache =
    _cache ||
    new NodeCache({
      stdTTL: DEFAULT_CACHE_TTLS.SIGNAL_STORE, // 5 minutes
      useClones: false,
      deleteOnExpire: true
    });

  const cacheMutex = new Mutex();

  function getUniqueId(type: string, id: string) {
    return `${type}.${id}`;
  }

  return {
    async get(type, ids) {
      return cacheMutex.runExclusive(async () => {
        const data: { [_: string]: SignalDataTypeMap[typeof type] } = {};
        const idsToFetch: string[] = [];
        for (const id of ids) {
          const item = cache.get<SignalDataTypeMap[typeof type]>(
            getUniqueId(type, id)
          );
          if (typeof item !== "undefined") {
            data[id] = item;
          } else {
            idsToFetch.push(id);
          }
        }

        if (idsToFetch.length) {
          logger.trace({ items: idsToFetch.length }, "loading from store");
          const fetched = await store.get(type, idsToFetch);
          for (const id of idsToFetch) {
            const item = fetched[id];
            if (item) {
              data[id] = item;
              cache.set(getUniqueId(type, id), item);
            }
          }
        }

        return data;
      });
    },
    async set(data) {
      return cacheMutex.runExclusive(async () => {
        let keys = 0;
        for (const type in data) {
          for (const id in data[type]) {
            cache.set(getUniqueId(type, id), data[type][id]);
            keys += 1;
          }
        }

        logger.trace({ keys }, "updated cache");

        await store.set(data);
      });
    },
    async clear() {
      cache.flushAll();
      await store.clear?.();
    }
  };
}

/**
 * Adds DB like transaction capability (https://en.wikipedia.org/wiki/Database_transaction) to the SignalKeyStore,
 * this allows batch read & write operations & improves the performance of the lib
 * @param state the key store to apply this capability to
 * @param logger logger to log events
 * @returns SignalKeyStore with transaction capability
 */
export const addTransactionCapability = (
  state: SignalKeyStore,
  logger: Logger,
  { maxCommitRetries, delayBetweenTriesMs }: TransactionCapabilityOptions
): SignalKeyStoreWithTransaction => {
  let inTransaction = false;
  // number of queries made to the DB during the transaction
  // only there for logging purposes
  let dbQueriesInTransaction = 0;
  let transactionCache: SignalDataSet = {};
  let mutations: SignalDataSet = {};
  // LRU Cache to hold mutexes for different key types
  const mutexCache = new LRUCache<string, Mutex>({
    ttl: 60 * 60 * 1000, // 1 hour
    ttlAutopurge: true,
    updateAgeOnGet: true
  });

  /**
   * prefetches some data and stores in memory,
   * useful if these data points will be used together often
   * */
  const prefetch = async (type: keyof SignalDataTypeMap, ids: string[]) => {
    const dict = transactionCache[type];
    const idsRequiringFetch = dict ? ids.filter(item => !(item in dict)) : ids;
    // only fetch if there are any items to fetch
    if (idsRequiringFetch.length) {
      dbQueriesInTransaction += 1;
      const result = await state.get(type, idsRequiringFetch);

      transactionCache[type] = Object.assign(
        transactionCache[type] || {},
        result
      );
    }
  };

  function getMutex(key: string): Mutex {
    let mutex = mutexCache.get(key);
    if (!mutex) {
      mutex = new Mutex();
      mutexCache.set(key, mutex);
      logger.info({ key }, "created new mutex");
    }

    return mutex;
  }

  function getTransactionMutex(key: string): Mutex {
    return getMutex(`transaction:${key}`);
  }

  function getKeyTypeMutex(type: string): Mutex {
    return getMutex(`keytype:${type}`);
  }

  async function handlePreKeyOperations(
    data: SignalDataSet,
    keyType: keyof SignalDataTypeMap,
    transactionCache: SignalDataSet,
    mutations: SignalDataSet,
    isInTransaction: boolean,
    state?: SignalKeyStore
  ): Promise<void> {
    const mutex = getKeyTypeMutex(keyType);

    await mutex.runExclusive(async () => {
      const keyData = data[keyType];
      if (!keyData) return;

      // Ensure structures exist
      transactionCache[keyType] = transactionCache[keyType] || ({} as any);
      mutations[keyType] = mutations[keyType] || ({} as any);

      // Separate deletions from updates for batch processing
      const deletionKeys: string[] = [];
      const updateKeys: string[] = [];

      for (const keyId in keyData) {
        if (keyData[keyId] === null) {
          deletionKeys.push(keyId);
        } else {
          updateKeys.push(keyId);
        }
      }

      // Process updates first (no validation needed)
      for (const keyId of updateKeys) {
        if (transactionCache[keyType]) {
          transactionCache[keyType]![keyId] = keyData[keyId]!;
        }

        if (mutations[keyType]) {
          mutations[keyType]![keyId] = keyData[keyId]!;
        }
      }

      // Process deletions with validation
      if (deletionKeys.length === 0) return;

      if (isInTransaction) {
        // In transaction, only allow deletion if key exists in cache
        for (const keyId of deletionKeys) {
          if (transactionCache[keyType]) {
            transactionCache[keyType]![keyId] = null;
            if (mutations[keyType]) {
              // Mark for deletion in mutations
              mutations[keyType]![keyId] = null;
            }
          } else {
            logger.warn(
              `Skipping deletion of non-existent ${keyType} in transaction: ${keyId}`
            );
          }
        }

        return;
      }

      // Outside transaction, batch validate all deletions
      if (!state) return;

      const existingKeys = await state.get(keyType, deletionKeys);
      for (const keyId of deletionKeys) {
        if (existingKeys[keyId]) {
          if (transactionCache[keyType])
            transactionCache[keyType]![keyId] = null;

          if (mutations[keyType]) mutations[keyType]![keyId] = null;
        } else {
          logger.warn(`Skipping deletion of non-existent ${keyType}: ${keyId}`);
        }
      }
    });
  }

  /**
   * Executes a function with mutexes acquired for given key types
   * Uses async-mutex's runExclusive with efficient batching
   */
  async function withMutexes<T>(
    keyTypes: string[],
    getKeyTypeMutex: (type: string) => Mutex,
    fn: () => Promise<T>
  ): Promise<T> {
    if (keyTypes.length === 0) {
      return fn();
    }

    if (keyTypes.length === 1) {
      return getKeyTypeMutex(keyTypes[0]!).runExclusive(fn);
    }

    // For multiple mutexes, sort by key type to prevent deadlocks
    // Then acquire all mutexes in order using Promise.all for better efficiency
    const sortedKeyTypes = [...keyTypes].sort();
    const mutexes = sortedKeyTypes.map(getKeyTypeMutex);

    // Acquire all mutexes in order to prevent deadlocks
    const releases: (() => void)[] = [];

    try {
      for (const mutex of mutexes) {
        releases.push(await mutex.acquire());
      }

      return await fn();
    } finally {
      // Release in reverse order
      while (releases.length > 0) {
        const release = releases.pop();
        if (release) release();
      }
    }
  }

  return {
    get: async (type, ids) => {
      if (inTransaction) {
        return await getKeyTypeMutex(type as string).runExclusive(async () => {
          await prefetch(type, ids);
          return ids.reduce((dict, id) => {
            const value = transactionCache[type]?.[id];
            if (value) {
              dict[id] = value;
            }
            return dict;
          }, {});
        });
      } else {
        return await getKeyTypeMutex(type as string).runExclusive(() =>
          state.get(type, ids)
        );
      }
    },
    set: async data => {
      if (inTransaction) {
        logger.trace({ types: Object.keys(data) }, "caching in transaction");
        for (const key in data) {
          transactionCache[key] = transactionCache[key] || {};
          if (key === "pre-key") {
            await handlePreKeyOperations(
              data,
              key,
              transactionCache,
              mutations,
              true
            );
          } else {
            Object.assign(transactionCache[key], data[key]);

            mutations[key] = mutations[key] || {};
            Object.assign(mutations[key], data[key]);
          }
        }
      } else {
        await withMutexes(Object.keys(data), getKeyTypeMutex, async () => {
          // Apply changes to the store
          await state.set(data);
        });
      }
    },
    isInTransaction: () => inTransaction,
    transaction: async function (work, key) {
      const releaseTxMutex = await getTransactionMutex(key).acquire();

      try {
        // if we're already in a transaction,
        // just execute what needs to be executed -- no commit required
        if (inTransaction) {
          releaseTxMutex();
          return await work();
        } else {
          logger.trace("entering transaction");
          inTransaction = true;
          releaseTxMutex();
          try {
            const result = await work();
            if (Object.keys(mutations).length) {
              logger.trace("committing transaction");
              // retry mechanism to ensure we've some recovery
              // in case a transaction fails in the first attempt
              let tries = maxCommitRetries;
              while (tries) {
                tries -= 1;
                try {
                  await state.set(mutations);
                  logger.trace(
                    { dbQueriesInTransaction },
                    "committed transaction"
                  );
                  break;
                } catch (error) {
                  logger.warn(
                    `failed to commit ${
                      Object.keys(mutations).length
                    } mutations, tries left=${tries}`
                  );
                  await delay(delayBetweenTriesMs);
                }
              }
            } else {
              logger.trace("no mutations in transaction");
            }

            return result;
          } finally {
            inTransaction = false;
            transactionCache = {};
            mutations = {};
            dbQueriesInTransaction = 0;
          }
        }
      } catch (error) {
        logger.error({ error }, "error in transaction");
        releaseTxMutex();
        throw error;
      }
    }
  };
};

export const initAuthCreds = (): AuthenticationCreds => {
  const identityKey = Curve.generateKeyPair();
  return {
    noiseKey: Curve.generateKeyPair(),
    pairingEphemeralKeyPair: Curve.generateKeyPair(),
    signedIdentityKey: identityKey,
    signedPreKey: signedKeyPair(identityKey, 1),
    registrationId: generateRegistrationId(),
    advSecretKey: randomBytes(32).toString("base64"),
    processedHistoryMessages: [],
    nextPreKeyId: 1,
    firstUnuploadedPreKeyId: 1,
    accountSyncCounter: 0,
    accountSettings: {
      unarchiveChats: false
    },
    pairingCode: undefined,
    registered: false,
    lastPropHash: undefined
  };
};
