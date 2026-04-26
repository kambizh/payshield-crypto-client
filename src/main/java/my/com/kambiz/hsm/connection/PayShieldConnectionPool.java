package my.com.kambiz.hsm.connection;

import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.exception.PayShieldException;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PreDestroy;

/**
 * Manages a pool of TCP connections to the payShield 10K.
 * Provides borrow/return semantics for thread-safe usage.
 */
public class PayShieldConnectionPool {

    private static final Logger log = LoggerFactory.getLogger(PayShieldConnectionPool.class);

    private final GenericObjectPool<PayShieldConnection> pool;

    public PayShieldConnectionPool(PayShieldProperties props) {
        GenericObjectPoolConfig<PayShieldConnection> config = new GenericObjectPoolConfig<>();
        config.setMaxTotal(props.getPoolMaxTotal());
        config.setMaxIdle(props.getPoolMaxIdle());
        config.setMinIdle(props.getPoolMinIdle());
        config.setTestOnBorrow(true);
        config.setTestOnReturn(true);
        config.setBlockWhenExhausted(true);

        this.pool = new GenericObjectPool<>(new PayShieldConnectionFactory(props), config);
        log.info("PayShield connection pool created: maxTotal={}, maxIdle={}, minIdle={}",
                props.getPoolMaxTotal(), props.getPoolMaxIdle(), props.getPoolMinIdle());
    }

    /**
     * Execute a command using a pooled connection.
     * Automatically borrows and returns the connection.
     */
    public byte[] execute(byte[] command) {
        PayShieldConnection conn = null;
        try {
            conn = pool.borrowObject();
            return conn.sendCommand(command);
        } catch (PayShieldException e) {
            throw e;
        } catch (Exception e) {
            throw new PayShieldException("Failed to execute HSM command", e);
        } finally {
            if (conn != null) {
                try {
                    pool.returnObject(conn);
                } catch (Exception e) {
                    log.warn("Error returning connection to pool", e);
                }
            }
        }
    }

    @PreDestroy
    public void shutdown() {
        log.info("Shutting down PayShield connection pool");
        pool.close();
    }

    /** Pool stats for monitoring */
    public String getPoolStats() {
        return String.format("active=%d, idle=%d, waiting=%d",
                pool.getNumActive(), pool.getNumIdle(), pool.getNumWaiters());
    }
}
