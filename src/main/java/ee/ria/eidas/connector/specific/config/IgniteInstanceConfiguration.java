package ee.ria.eidas.connector.specific.config;

import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.FileUrlResource;
import org.springframework.util.Assert;

import javax.cache.Cache;
import java.io.File;
import java.io.IOException;

import static ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.CacheNames.*;

@Configuration
public class IgniteInstanceConfiguration {

    @Lazy
    @Bean
    public Ignite igniteClient(@Value("#{environment.EIDAS_CONFIG_REPOSITORY}/igniteSpecificCommunication.xml") String igniteConfig) throws IOException {
        Assert.isTrue(new File(igniteConfig).exists(), "Required Ignite configuration file not found: " + igniteConfig);
        Ignition.setClientMode(true);
        IgniteConfiguration cfg = Ignition.loadSpringBean(new FileUrlResource(igniteConfig).getInputStream(), "igniteSpecificCommunication.cfg");
        cfg.setIgniteInstanceName(cfg.getIgniteInstanceName() + "Client");
        return Ignition.getOrStart(cfg);
    }

    @Lazy
    @Bean("specificNodeConnectorRequestCache")
    public Cache<String, String> specificNodeConnectorRequestCache(Ignite igniteClient) {
        return igniteClient.cache(INCOMING_NODE_REQUESTS_CACHE.getName());
    }

    @Lazy
    @Bean("nodeSpecificConnectorResponseCache")
    public Cache<String, String> nodeSpecificConnectorResponseCache(Ignite igniteClient) {
        return igniteClient.cache(OUTGOING_NODE_RESPONSES_CACHE.getName());
    }

    @Lazy
    @Bean("specificMSSpRequestCorrelationMap")
    public Cache<String, String> specificMSSpRequestCorrelationMap(Ignite igniteClient) {
        return igniteClient.cache(SP_REQUEST_CORRELATION_CACHE.getName());
    }
}
