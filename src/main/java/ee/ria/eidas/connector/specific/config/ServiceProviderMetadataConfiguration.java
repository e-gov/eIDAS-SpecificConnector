package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ServiceProvider;
import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadataResolver;
import ee.ria.eidas.connector.specific.monitoring.health.ServiceProviderMetadataHealthIndicator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static java.lang.String.format;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ServiceProviderMetadataConfiguration {
    private final HealthContributorRegistry healthContributorRegistry;
    private final SpecificConnectorProperties connectorProperties;
    private final ParserPool parserPool;

    @Bean
    public ServiceProviderMetadataResolver serviceProviders() throws ResolverException, ComponentInitializationException, CertificateException {
        List<ServiceProviderMetadata> spMetadataResolvers = new ArrayList<>();
        if(connectorProperties.getServiceProviders() !=  null) {
            for (ServiceProvider serviceProvider : connectorProperties.getServiceProviders()) {
                ServiceProviderMetadata serviceProviderMetadata = ServiceProviderMetadata.builder()
                        .serviceProvider(serviceProvider)
                        .parserPool(parserPool)
                        .build();
                spMetadataResolvers.add(serviceProviderMetadata);
                registerHealthIndicator(serviceProviderMetadata);
            }
        }
        return new ServiceProviderMetadataResolver(spMetadataResolvers);
    }

    private void registerHealthIndicator(ServiceProviderMetadata serviceProviderMetadata) {
        String name = format("sp-%s-metadata", serviceProviderMetadata.getServiceProvider().getId());
        log.info("Registering {} health indicator", name);
        healthContributorRegistry.registerContributor(name, new ServiceProviderMetadataHealthIndicator(serviceProviderMetadata));
    }
}
