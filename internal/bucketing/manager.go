package bucketing

import (
	"auth-service/internal/config"
	"fmt"
	"hash"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spaolacci/murmur3"
)

type BucketingManager struct {
	userBuckets  int
	eventBuckets int
	hasherPool   sync.Pool
	config       *config.Config
}

type BucketAssignment struct {
	UserBucket  int    `json:"user_bucket"`
	EventBucket int    `json:"event_bucket"`
	TimeBucket  int64  `json:"time_bucket"`
	DateBucket  string `json:"date_bucket"`
}

func NewBucketingManager(cfg *config.Config) *BucketingManager {
	bm := &BucketingManager{
		userBuckets:  cfg.Bucketing.UserBuckets,
		eventBuckets: cfg.Bucketing.EventBuckets,
		config:       cfg,
	}

	// Create pool of hash functions to avoid allocation overhead
	bm.hasherPool = sync.Pool{
		New: func() interface{} {
			return murmur3.New64()
		},
	}

	return bm
}

// GetUserBucket returns consistent bucket for user (0 to userBuckets-1)
func (bm *BucketingManager) GetUserBucket(userID interface{}) int {
	var idStr string

	switch v := userID.(type) {
	case string:
		idStr = v
	case uuid.UUID:
		idStr = v.String()
	case int, int64:
		idStr = strconv.FormatInt(v.(int64), 10)
	default:
		idStr = toString(v)
	}

	return bm.getBucket(idStr, bm.userBuckets)
}

// GetEventBucket returns bucket for events/rate limiting
func (bm *BucketingManager) GetEventBucket(identifier string) int {
	return bm.getBucket(identifier, bm.eventBuckets)
}

// GetTimeBucket returns time bucket for OTP/rate limiting
func (bm *BucketingManager) GetTimeBucket(windowSeconds int) int64 {
	return time.Now().Unix() / int64(windowSeconds) * int64(windowSeconds)
}

// GetDateBucket returns date bucket for events
func (bm *BucketingManager) GetDateBucket() string {
	return time.Now().UTC().Format("2006-01-02")
}

// GetBucketAssignment returns all bucket assignments for a user
func (bm *BucketingManager) GetBucketAssignment(userID interface{}) *BucketAssignment {
	return &BucketAssignment{
		UserBucket:  bm.GetUserBucket(userID),
		EventBucket: bm.GetEventBucket(toString(userID)),
		TimeBucket:  bm.GetTimeBucket(300), // 5-minute windows
		DateBucket:  bm.GetDateBucket(),
	}
}

// GetShardKey generates shard key for distributed systems
func (bm *BucketingManager) GetShardKey(userID interface{}, totalShards int) int {
	bucket := bm.GetUserBucket(userID)
	return bucket % totalShards
}

// GetConsistentHashes returns multiple consistent hashes for redundancy
func (bm *BucketingManager) GetConsistentHashes(key string, count int) []uint64 {
	hashes := make([]uint64, count)

	for i := 0; i < count; i++ {
		seed := uint32(i)
		hasher := murmur3.New64WithSeed(seed)
		hasher.Write([]byte(key))
		hashes[i] = hasher.Sum64()
	}

	return hashes
}

// GetWeightedBucket returns bucket with weighted distribution
func (bm *BucketingManager) GetWeightedBucket(key string, weights []float64) int {
	if len(weights) == 0 {
		return 0
	}

	hash := bm.getHash(key)
	totalWeight := 0.0
	for _, w := range weights {
		totalWeight += w
	}

	// Normalize hash to [0,1) range
	normalized := float64(hash%10000) / 10000.0
	normalized *= totalWeight

	cumulative := 0.0
	for i, w := range weights {
		cumulative += w
		if normalized < cumulative {
			return i
		}
	}

	return len(weights) - 1
}

// Private methods
func (bm *BucketingManager) getBucket(key string, numBuckets int) int {
	hash := bm.getHash(key)
	return int(hash % uint64(numBuckets))
}

func (bm *BucketingManager) getHash(key string) uint64 {
	// Get hasher from pool
	hasher := bm.hasherPool.Get().(hash.Hash64)
	defer bm.hasherPool.Put(hasher)

	// Reset hasher for reuse
	hasher.Reset()
	hasher.Write([]byte(key))
	return hasher.Sum64()
}

func toString(v interface{}) string {
	switch v := v.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Benchmark bucketing performance
func (bm *BucketingManager) Benchmark(iterations int) (avgTime time.Duration) {
	start := time.Now()

	for i := 0; i < iterations; i++ {
		testID := fmt.Sprintf("user%d@example.com", i)
		bm.GetUserBucket(testID)
	}

	return time.Since(start) / time.Duration(iterations)
}
func (bm *BucketingManager) GetUserBuckets() int {
	return bm.userBuckets
}

// GetEventBuckets returns the number of event buckets
func (bm *BucketingManager) GetEventBuckets() int {
	return bm.eventBuckets
}
