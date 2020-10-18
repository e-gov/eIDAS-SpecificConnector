package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ServiceProvider;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.math.BigDecimal;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ServiceProviderMetadataConfiguration {
    private final SpecificConnectorProperties specificConnectorProperties;
    private final KeyStore responderMetadataTrustStore;

    @Bean
    public List<ServiceProviderMetadata> serviceProviders() throws ResolverException, KeyStoreException, ComponentInitializationException {
        List<ServiceProviderMetadata> serviceProviderMetadataResolvers = new ArrayList<>();
        for (ServiceProvider serviceProvider : specificConnectorProperties.getServiceProviders()) {
            serviceProviderMetadataResolvers.add(setupServiceProviderMetadataResolver(serviceProvider));
        }
        return serviceProviderMetadataResolvers;
    }

    private ServiceProviderMetadata setupServiceProviderMetadataResolver(ServiceProvider serviceProvider)
            throws ResolverException, KeyStoreException, ComponentInitializationException {
        log.info("Initializing metadata resolver for: {}", serviceProvider);
        Long minRefreshDelay = specificConnectorProperties.getServiceProviderMetadataMinRefreshDelay();
        Long maxRefreshDelay = specificConnectorProperties.getServiceProviderMetadataMaxRefreshDelay();
        BigDecimal delayFactor = specificConnectorProperties.getServiceProviderMetadataRefreshDelayFactor();

        return ServiceProviderMetadata.builder()
                .serviceProvider(serviceProvider)
                .responderTrustStore(responderMetadataTrustStore)
                .minRefreshDelay(minRefreshDelay)
                .maxRefreshDelay(maxRefreshDelay)
                .refreshDelayFactor(delayFactor.floatValue())
                .build();
    }
}
