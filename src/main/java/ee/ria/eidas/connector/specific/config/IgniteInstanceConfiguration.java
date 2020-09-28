package ee.ria.eidas.connector.specific.config;

import org.apache.ignite.Ignite;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.cache.Cache;
import java.io.IOException;

import static ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.CacheProperties.CacheNames.*;

@Configuration
public class IgniteInstanceConfiguration {

    @Lazy
    @Bean
    public Ignite igniteClient(SpecificConnectorProperties specificConnectorProperties, ResourceLoader resourceLoader) throws IOException {
        SpecificConnectorProperties.CacheProperties cacheProperties = specificConnectorProperties.getCommunicationCache();
        Resource igniteConfiguration = getIgniteConfiguration(cacheProperties, resourceLoader);
        Ignition.setClientMode(true);
        IgniteConfiguration cfg = Ignition.loadSpringBean(igniteConfiguration.getInputStream(), cacheProperties.getIgniteConfigurationBeanName());
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

    private Resource getIgniteConfiguration(SpecificConnectorProperties.CacheProperties properties, ResourceLoader resourceLoader) {
        Resource resource = resourceLoader.getResource(properties.getIgniteConfigurationFileLocation());
        if (!resource.exists())
            throw new IllegalStateException("Required Ignite configuration file not found: " + properties.getIgniteConfigurationFileLocation());
        return resource;
    }
}
