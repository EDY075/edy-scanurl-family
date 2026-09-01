export interface RateLimitDecision {
  allowed: boolean;
  retryAfterSeconds: number;
  remaining: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

export class InMemoryTokenBucket {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly capacity = 8,
    private readonly refillPerMinute = 4,
    private readonly maxBuckets = 10_000,
    private readonly ttlMs = 60 * 60_000,
  ) {}

  consume(key: string, now = Date.now()): RateLimitDecision {
    this.prune(now);
    const previous = this.buckets.get(key) ?? { tokens: this.capacity, updatedAt: now };
    const elapsedMinutes = Math.max(0, now - previous.updatedAt) / 60_000;
    const available = Math.min(this.capacity, previous.tokens + elapsedMinutes * this.refillPerMinute);
    if (available < 1) {
      const retryAfterSeconds = Math.max(1, Math.ceil(((1 - available) / this.refillPerMinute) * 60));
      this.buckets.set(key, { tokens: available, updatedAt: now });
      return { allowed: false, retryAfterSeconds, remaining: 0 };
    }
    const tokens = available - 1;
    this.ensureCapacity();
    this.buckets.set(key, { tokens, updatedAt: now });
    return { allowed: true, retryAfterSeconds: 0, remaining: Math.floor(tokens) };
  }

  private prune(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > this.ttlMs) this.buckets.delete(key);
    }
  }

  private ensureCapacity(): void {
    if (this.buckets.size < this.maxBuckets) return;
    const oldest = [...this.buckets.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt)[0];
    if (oldest) this.buckets.delete(oldest[0]);
  }
}
