package my.com.kambiz.hsm.connection;

import my.com.kambiz.hsm.config.PayShieldProperties;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.DestroyMode;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating and managing pooled payShield connections.
 */
public class PayShieldConnectionFactory extends BasePooledObjectFactory<PayShieldConnection> {

    private static final Logger log = LoggerFactory.getLogger(PayShieldConnectionFactory.class);

    private final PayShieldProperties properties;

    public PayShieldConnectionFactory(PayShieldProperties properties) {
        this.properties = properties;
    }

    @Override
    public PayShieldConnection create() {
        log.debug("Creating new PayShield connection to {}:{}", properties.getHost(), properties.getPort());
        return new PayShieldConnection(properties);
    }

    @Override
    public PooledObject<PayShieldConnection> wrap(PayShieldConnection connection) {
        return new DefaultPooledObject<>(connection);
    }

    @Override
    public boolean validateObject(PooledObject<PayShieldConnection> p) {
        return p.getObject().isValid();
    }

    @Override
    public void destroyObject(PooledObject<PayShieldConnection> p, DestroyMode mode) {
        log.debug("Destroying PayShield connection");
        p.getObject().close();
    }
}
