import type { BlueGreenDeploymentState, BlueGreenSensorStatus } from './types.js';
import { buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, type RedisKv } from '../../storage/redis/index.js';

export interface DeploymentStateStore {
  loadAll(): Promise<BlueGreenDeploymentState[]>;
  getByDeploymentId(deploymentId: string): Promise<BlueGreenDeploymentState | null>;
  upsert(state: BlueGreenDeploymentState): Promise<void>;
  delete(tenantId: string, deploymentId: string): Promise<void>;
}

export class NoopDeploymentStateStore implements DeploymentStateStore {
  async loadAll(): Promise<BlueGreenDeploymentState[]> {
    return [];
  }
  async getByDeploymentId(_deploymentId: string): Promise<BlueGreenDeploymentState | null> {
    return null;
  }
  async upsert(_state: BlueGreenDeploymentState): Promise<void> {
    // no-op
  }
  async delete(_tenantId: string, _deploymentId: string): Promise<void> {
    // no-op
  }
}

type StoredBlueGreenSensorStatus = Omit<BlueGreenSensorStatus, 'lastUpdated'> & { lastUpdated: string };

type StoredBlueGreenDeploymentState = Omit<
  BlueGreenDeploymentState,
  'sensorStatus' | 'stagedAt' | 'activatedAt' | 'retiredAt'
> & {
  stagedAt?: string;
  activatedAt?: string;
  retiredAt?: string;
  sensorStatus: StoredBlueGreenSensorStatus[];
};

type DeploymentIndexEntry = { tenantId: string; deploymentId: string };

function serializeSensorStatus(status: BlueGreenSensorStatus): StoredBlueGreenSensorStatus {
  return { ...status, lastUpdated: status.lastUpdated.toISOString() };
}

function deserializeSensorStatus(status: StoredBlueGreenSensorStatus): BlueGreenSensorStatus {
  return { ...status, lastUpdated: new Date(status.lastUpdated) };
}

function serializeState(state: BlueGreenDeploymentState): StoredBlueGreenDeploymentState {
  return {
    ...state,
    stagedAt: state.stagedAt?.toISOString(),
    activatedAt: state.activatedAt?.toISOString(),
    retiredAt: state.retiredAt?.toISOString(),
    sensorStatus: Array.from(state.sensorStatus.values()).map(serializeSensorStatus),
  };
}

function deserializeState(state: StoredBlueGreenDeploymentState): BlueGreenDeploymentState {
  return {
    ...state,
    stagedAt: state.stagedAt ? new Date(state.stagedAt) : undefined,
    activatedAt: state.activatedAt ? new Date(state.activatedAt) : undefined,
    retiredAt: state.retiredAt ? new Date(state.retiredAt) : undefined,
    sensorStatus: new Map(state.sensorStatus.map((s) => [s.sensorId, deserializeSensorStatus(s)])),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class RedisDeploymentStateStore implements DeploymentStateStore {
  private kv: RedisKv;
  private namespace: string;
  private version: number;
  private stateDataType: string;
  private byIdDataType: string;
  private indexTenantId: string;
  private indexDataType: string;
  private indexId: string;
  private lockTtlSeconds: number;

  constructor(
    kv: RedisKv,
    options: {
      namespace?: string;
      version?: number;
      stateDataType?: string;
      indexTenantId?: string;
      indexDataType?: string;
      indexId?: string;
      lockTtlSeconds?: number;
    } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.stateDataType = options.stateDataType ?? 'blue-green-deployment';
    this.byIdDataType = 'blue-green-deployment-by-id';
    this.indexTenantId = options.indexTenantId ?? 'global';
    this.indexDataType = options.indexDataType ?? 'blue-green-deployment-index';
    this.indexId = options.indexId ?? 'all';
    this.lockTtlSeconds = options.lockTtlSeconds ?? TTL_SECONDS.lockMin;
  }

  private stateKey(tenantId: string, deploymentId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.stateDataType,
      id: deploymentId,
    });
  }

  private indexKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: this.indexTenantId,
      dataType: this.indexDataType,
      id: this.indexId,
    });
  }

  private byIdKey(deploymentId: string): string {
    // Map deploymentId -> tenantId to enable cross-instance updates when tenant context is missing.
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: this.indexTenantId,
      dataType: this.byIdDataType,
      id: deploymentId,
    });
  }

  private indexLockKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: this.indexTenantId,
      dataType: 'lock',
      id: [this.indexDataType, this.indexId],
    });
  }

  private async withIndexLock<T>(fn: () => Promise<T>): Promise<T> {
    const lockKey = this.indexLockKey();

    let lockAcquired = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      lockAcquired = await this.kv.set(lockKey, '1', { ttlSeconds: this.lockTtlSeconds, ifNotExists: true });
      if (lockAcquired) break;
      await sleep(25 * (attempt + 1));
    }

    try {
      return await fn();
    } finally {
      if (lockAcquired) await this.kv.del(lockKey);
    }
  }

  private async readIndex(): Promise<DeploymentIndexEntry[]> {
    const raw = await this.kv.get(this.indexKey());
    if (!raw) return [];
    return jsonDecode<DeploymentIndexEntry[]>(raw, { maxBytes: 1024 * 1024 });
  }

  private async writeIndex(entries: DeploymentIndexEntry[]): Promise<void> {
    // Keep index around while deployments are active; refresh on each upsert/delete.
    await this.kv.set(this.indexKey(), jsonEncode(entries), { ttlSeconds: TTL_SECONDS.session });
  }

  async loadAll(): Promise<BlueGreenDeploymentState[]> {
    const entries = await this.readIndex();
    const loaded: BlueGreenDeploymentState[] = [];
    const stillPresent: DeploymentIndexEntry[] = [];

    for (const entry of entries) {
      const raw = await this.kv.get(this.stateKey(entry.tenantId, entry.deploymentId));
      if (!raw) continue;

      const parsed = jsonDecode<StoredBlueGreenDeploymentState>(raw, { maxBytes: 1024 * 1024 });
      loaded.push(deserializeState(parsed));
      stillPresent.push(entry);

      // Best-effort backfill: ensure deploymentId -> tenantId pointer exists.
      await this.kv
        .set(this.byIdKey(entry.deploymentId), entry.tenantId, { ttlSeconds: TTL_SECONDS.session })
        .catch(() => {});
    }

    // Best-effort cleanup of stale index entries. Keep this under lock to reduce
    // risk of dropping concurrent upserts from other hub instances.
    if (stillPresent.length !== entries.length) {
      await this.withIndexLock(async () => {
        const current = await this.readIndex();
        const filtered: DeploymentIndexEntry[] = [];
        for (const entry of current) {
          const raw = await this.kv.get(this.stateKey(entry.tenantId, entry.deploymentId));
          if (raw) filtered.push(entry);
        }
        await this.writeIndex(filtered);
      });
    }

    return loaded;
  }

  async getByDeploymentId(deploymentId: string): Promise<BlueGreenDeploymentState | null> {
    const tenantId = await this.kv.get(this.byIdKey(deploymentId));
    if (!tenantId) return null;

    const raw = await this.kv.get(this.stateKey(tenantId, deploymentId));
    if (!raw) return null;

    const parsed = jsonDecode<StoredBlueGreenDeploymentState>(raw, { maxBytes: 1024 * 1024 });
    return deserializeState(parsed);
  }

  async upsert(state: BlueGreenDeploymentState): Promise<void> {
    const ttlSeconds = TTL_SECONDS.session;
    await this.kv.set(this.stateKey(state.tenantId, state.deploymentId), jsonEncode(serializeState(state)), {
      ttlSeconds,
    });
    await this.kv.set(this.byIdKey(state.deploymentId), state.tenantId, { ttlSeconds });

    await this.withIndexLock(async () => {
      const entries = await this.readIndex();
      const exists = entries.some((e) => e.tenantId === state.tenantId && e.deploymentId === state.deploymentId);
      if (!exists) entries.push({ tenantId: state.tenantId, deploymentId: state.deploymentId });
      await this.writeIndex(entries);
    });
  }

  async delete(tenantId: string, deploymentId: string): Promise<void> {
    await this.kv.del(this.stateKey(tenantId, deploymentId));
    await this.kv.del(this.byIdKey(deploymentId));

    await this.withIndexLock(async () => {
      const entries = await this.readIndex();
      const next = entries.filter((e) => !(e.tenantId === tenantId && e.deploymentId === deploymentId));
      await this.writeIndex(next);
    });
  }
}
