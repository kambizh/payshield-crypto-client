package my.com.kambiz.hsm.connection;

import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.exception.PayShieldException;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PreDestroy;
import java.time.Duration;

/**
 * Production-grade connection pool for the payShield 10K HSM.
 *
 * Concurrency model:
 *   - Each thread borrows its own dedicated TCP connection from the pool
 *   - Multiple threads execute HSM commands in parallel (up to poolMaxTotal)
 *   - No serialization between threads — true concurrent HSM access
 *   - Connection is returned to pool after each operation
 *
 * The payShield 10K supports concurrent connections on a single port.
 * The number of parallel operations is bounded by poolMaxTotal.
 *
 * For RPP runtime signing throughput, set poolMaxTotal to match your
 * expected peak concurrent transactions (e.g., 20-50 for high volume).
 *
 * Error handling:
 *   - Broken connections are invalidated (not returned to pool)
 *   - Borrow timeout prevents indefinite blocking
 *   - Idle connection eviction prevents stale socket issues
 */
public class PayShieldConnectionPool {

    private static final Logger log = LoggerFactory.getLogger(PayShieldConnectionPool.class);

    private final GenericObjectPool<PayShieldConnection> pool;

    public PayShieldConnectionPool(PayShieldProperties props) {
        GenericObjectPoolConfig<PayShieldConnection> config = new GenericObjectPoolConfig<>();

        // === Pool sizing ===
        // maxTotal = max concurrent HSM operations
        // For runtime signing: set to expected peak concurrent RPP transactions
        config.setMaxTotal(props.getPoolMaxTotal());
        config.setMaxIdle(props.getPoolMaxIdle());
        config.setMinIdle(props.getPoolMinIdle());

        // === Borrow behavior ===
        // Block when all connections are in use, but with a timeout
        config.setBlockWhenExhausted(true);
        config.setMaxWait(Duration.ofMillis(props.getPoolBorrowTimeoutMs()));

        // === Validation ===
        // Test connection health when borrowing (catches dead sockets)
        // Skip testOnReturn to reduce overhead under high throughput
        config.setTestOnBorrow(true);
        config.setTestOnReturn(false);
        // Periodic validation of idle connections
        config.setTestWhileIdle(true);

        // === Idle connection eviction ===
        // Evict connections idle longer than 5 minutes (stale TCP sockets)
        config.setTimeBetweenEvictionRuns(Duration.ofSeconds(30));
        config.setMinEvictableIdleDuration(Duration.ofMinutes(5));
        // Keep minIdle connections alive even if idle
        config.setSoftMinEvictableIdleDuration(Duration.ofMinutes(10));

        // === LIFO ===
        // Use LIFO (last-in-first-out) so the most recently used connection
        // is borrowed first — keeps connections warm and reduces stale socket risk
        config.setLifo(true);

        // === JMX (optional, for monitoring) ===
        config.setJmxEnabled(true);
        config.setJmxNamePrefix("payshield-pool");

        this.pool = new GenericObjectPool<>(new PayShieldConnectionFactory(props), config);

        log.info("PayShield connection pool created: host={}, port={}, lmkMode={}, " +
                        "maxTotal={}, maxIdle={}, minIdle={}, borrowTimeout={}ms",
                props.getHost(), props.getActivePort(), props.getLmkMode(),
                props.getPoolMaxTotal(), props.getPoolMaxIdle(), props.getPoolMinIdle(),
                props.getPoolBorrowTimeoutMs());
    }

    /**
     * Execute a command using a pooled connection.
     *
     * Thread-safe: each calling thread gets its own connection.
     * Multiple threads can execute concurrently up to poolMaxTotal.
     *
     * If a communication error occurs, the connection is invalidated
     * (destroyed) rather than returned to the pool, preventing a
     * broken connection from being reused.
     */
    public byte[] execute(byte[] command) {
        PayShieldConnection conn = null;
        boolean broken = false;
        try {
            conn = pool.borrowObject();
            return conn.sendCommand(command);
        } catch (PayShieldException e) {
            // HSM command errors (error codes) — connection is still healthy
            // Communication errors — connection is broken
            if (isCommunicationError(e)) {
                broken = true;
            }
            throw e;
        } catch (java.util.NoSuchElementException e) {
            // Pool exhausted and borrow timed out
            throw new PayShieldException(
                    "HSM connection pool exhausted (all " + pool.getMaxTotal() +
                            " connections in use). Consider increasing payshield.pool-max-total. " +
                            "Pool stats: " + getPoolStats(), e);
        } catch (Exception e) {
            broken = true;
            throw new PayShieldException("Failed to execute HSM command", e);
        } finally {
            if (conn != null) {
                try {
                    if (broken) {
                        // Destroy broken connection — don't return it to the pool
                        pool.invalidateObject(conn);
                        log.warn("Invalidated broken HSM connection. Pool stats: {}", getPoolStats());
                    } else {
                        pool.returnObject(conn);
                    }
                } catch (Exception e) {
                    log.warn("Error managing connection lifecycle", e);
                }
            }
        }
    }

    /**
     * Determine if an exception indicates a broken connection (vs. an HSM command error).
     * HSM command errors (error codes like AB, 02, etc.) mean the connection is fine.
     * IOException-rooted errors mean the TCP connection is broken.
     */
    private boolean isCommunicationError(PayShieldException e) {
        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof java.io.IOException) {
                return true;
            }
            cause = cause.getCause();
        }
        // Check for connection-level error messages
        String msg = e.getMessage();
        return msg != null && (
                msg.contains("communication error") ||
                msg.contains("connection closed") ||
                msg.contains("Short read"));
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down PayShield connection pool. Final stats: {}", getPoolStats());
        pool.close();
    }

    /** One-line pool snapshot string for log lines. */
    public String getPoolStats() {
        return String.format("active=%d, idle=%d, waiting=%d, maxTotal=%d",
                pool.getNumActive(), pool.getNumIdle(), pool.getNumWaiters(), pool.getMaxTotal());
    }

    /**
     * Structured pool snapshot for REST responses and stress-test reporting.
     *
     * Instant counters (point-in-time):
     *   active   – connections currently borrowed by threads
     *   idle     – connections sitting idle, ready for immediate use
     *   waiting  – threads blocked waiting for a connection
     *   maxTotal – configured pool ceiling
     *
     * Cumulative counters (since JVM start / pool creation):
     *   totalBorrows   – every successful borrowObject() call
     *   totalReturns   – every returnObject() call (should track borrows)
     *   totalCreated   – physical TCP connections opened
     *   totalDestroyed – physical TCP connections closed / invalidated
     *
     * Wait-time metrics (cumulative, ms):
     *   meanBorrowWaitMs – rolling mean of time threads spent waiting for a borrow
     *   maxBorrowWaitMs  – worst-case borrow wait seen so far
     *
     * Under a concurrent stress test:
     *   - (totalBorrowsAfter - totalBorrowsBefore) == expected HSM calls
     *   - maxBorrowWaitMs > 0 → pool was contended (connections were shared)
     *   - totalCreated > 1    → pool scaled up from the min-idle baseline
     */
    public java.util.Map<String, Object> getDetailedPoolStats() {
        java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("active",           pool.getNumActive());
        m.put("idle",             pool.getNumIdle());
        m.put("waiting",          pool.getNumWaiters());
        m.put("maxTotal",         pool.getMaxTotal());
        m.put("totalBorrows",     pool.getBorrowedCount());
        m.put("totalReturns",     pool.getReturnedCount());
        m.put("totalCreated",     pool.getCreatedCount());
        m.put("totalDestroyed",   pool.getDestroyedCount());
        m.put("meanBorrowWaitMs", Math.round(pool.getMeanBorrowWaitTimeMillis()));
        m.put("maxBorrowWaitMs",  pool.getMaxBorrowWaitTimeMillis());
        return m;
    }

    /** Number of connections currently in use by threads. */
    public int getActiveCount() { return pool.getNumActive(); }

    /** Number of idle connections available for immediate use. */
    public int getIdleCount() { return pool.getNumIdle(); }

    /** Number of threads waiting for a connection. */
    public int getWaitingCount() { return pool.getNumWaiters(); }

    /** Total borrow count since startup (for throughput monitoring). */
    public long getBorrowedCount() { return pool.getBorrowedCount(); }
}