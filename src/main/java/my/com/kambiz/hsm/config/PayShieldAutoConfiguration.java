package my.com.kambiz.hsm.config;

import my.com.kambiz.hsm.connection.PayShieldConnectionPool;
import my.com.kambiz.hsm.service.HsmCryptoService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Spring Boot auto-configuration for the payshield-crypto-client library.
 * Automatically creates the connection pool and service beans when
 * the payshield.host property is set.
 */
@AutoConfiguration
@EnableConfigurationProperties(PayShieldProperties.class)
@ConditionalOnProperty(prefix = "payshield", name = "host")
public class PayShieldAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(PayShieldAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public PayShieldConnectionPool payShieldConnectionPool(PayShieldProperties properties) {
        LmkMode mode = properties.getResolvedLmkMode();
        log.info("HSM Config -> host={}, activePort={}, lmkMode={}, variantPort={}, keyBlockPort={}",
                properties.getHost(), properties.getActivePort(), mode,
                properties.getPort(), properties.getPortKeyBlock());
        return new PayShieldConnectionPool(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HsmCryptoService hsmCryptoService(PayShieldConnectionPool connectionPool,
                                             PayShieldProperties properties) {
        return new HsmCryptoService(connectionPool, properties);
    }
}