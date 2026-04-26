package my.com.kambiz.hsm.config;

import my.com.kambiz.hsm.connection.PayShieldConnectionPool;
import my.com.kambiz.hsm.service.HsmCryptoService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for the hsm-crypto-starter library.
 * Automatically creates the connection pool and service beans when
 * the payshield.host property is set.
 */
@AutoConfiguration
@EnableConfigurationProperties(PayShieldProperties.class)
@ConditionalOnProperty(prefix = "payshield", name = "host")
public class PayShieldAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PayShieldConnectionPool payShieldConnectionPool(PayShieldProperties properties) {
        return new PayShieldConnectionPool(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HsmCryptoService hsmCryptoService(PayShieldConnectionPool connectionPool,
                                             PayShieldProperties properties) {
        return new HsmCryptoService(connectionPool, properties);
    }
}
