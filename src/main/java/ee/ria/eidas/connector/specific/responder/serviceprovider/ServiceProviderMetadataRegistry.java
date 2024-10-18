package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.monitoring.health.ServiceProviderMetadataHealthIndicator;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static java.util.stream.Collectors.toMap;

@Slf4j
@RequiredArgsConstructor
@Component
public class ServiceProviderMetadataRegistry {
    private final HealthContributorRegistry healthContributorRegistry;
    private final List<ServiceProviderMetadata> serviceProviders;
    private Map<String, ServiceProviderMetadata> spMetadataEntityIdMap;

    @PostConstruct
    private void initialize() {
        spMetadataEntityIdMap = serviceProviders.stream()
                .collect(toMap(ServiceProviderMetadata::getEntityId, sp -> sp));
        serviceProviders.forEach(this::registerHealthContributor);
    }

    private void registerHealthContributor(ServiceProviderMetadata sp) {
        String name = format("sp-%s-metadata", sp.getId());
        log.info("Registering {} health indicator", name);
        healthContributorRegistry.registerContributor(name, new ServiceProviderMetadataHealthIndicator(sp));
    }

    public void refreshMetadata(String issuerId) throws ResolverException {
        get(issuerId).refreshMetadata();
    }

    @Nullable
    public ServiceProviderMetadata get(String issuerId) {
        return spMetadataEntityIdMap.get(issuerId);
    }
}
