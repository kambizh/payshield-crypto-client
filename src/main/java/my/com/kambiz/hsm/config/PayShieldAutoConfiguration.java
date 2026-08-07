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

    /** Build marker — appears in startup logs so you can confirm the deployed JAR has LMK-ID support. */
    public static final String BUILD_FEATURE_MARKER = "EI-LMK-ID-SUPPORT-v1";

    @Bean
    @ConditionalOnMissingBean
    public PayShieldConnectionPool payShieldConnectionPool(PayShieldProperties properties) {
        LmkMode mode = properties.getResolvedLmkMode();
        String lmkId = properties.getResolvedLmkId();
        boolean lmkIdEnabled = lmkId != null;

        log.info("=================================================================");
        log.info("payshield-crypto-client build marker: {}", BUILD_FEATURE_MARKER);
        log.info("HSM Config -> host={}, activePort={}, lmkMode={}",
                properties.getHost(), properties.getActivePort(), mode);
        log.info("HSM Ports  -> variantPort={}, keyBlockPort={}",
                properties.getPort(), properties.getPortKeyBlock());
        log.info("HSM LMK ID -> enabled={}, lmkId={}  (00=Variant, 01=KeyBlock)",
                lmkIdEnabled, lmkIdEnabled ? lmkId : "(blank — dual-port / no % field)");
        if (lmkIdEnabled) {
            log.info("EI sample  -> ...%{}#{}00   e.g. 0000EI0204801%{}#{}00",
                    lmkId, properties.getKeyBlockKeyVersion(),
                    lmkId, properties.getKeyBlockKeyVersion());
        } else {
            log.info("EI sample  -> KeyBlock: ...#{}00  |  Variant: no % / # trailer",
                    properties.getKeyBlockKeyVersion());
        }
        log.info("=================================================================");

        return new PayShieldConnectionPool(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public HsmCryptoService hsmCryptoService(PayShieldConnectionPool connectionPool,
                                             PayShieldProperties properties) {
        log.info("HsmCryptoService ready [{}] lmkMode={} lmkId={}",
                BUILD_FEATURE_MARKER,
                properties.getResolvedLmkMode(),
                properties.getResolvedLmkId() == null ? "(none)" : properties.getResolvedLmkId());
        return new HsmCryptoService(connectionPool, properties);
    }
}