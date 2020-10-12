package ee.ria.eidas.connector.specific.metadata.sp;

import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.monitoring.health.ServiceProviderMetadataHealthIndicator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
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
                .peek(this::registerHealthContributor)
                .collect(toMap(ServiceProviderMetadata::getEntityId, sp -> sp));
    }

    private void registerHealthContributor(ServiceProviderMetadata sp) {
        String name = format("sp-%s-metadata", sp.getId());
        log.info("Registering {} health indicator", name);
        healthContributorRegistry.registerContributor(name, new ServiceProviderMetadataHealthIndicator(sp));
    }

    public void refreshMetadata(String entityId) throws ResolverException {
        getByEntityId(entityId).refreshMetadata();
        ;
    }

    public ServiceProviderMetadata getByEntityId(String entityId) {
        ServiceProviderMetadata serviceProviderMetadata = spMetadataEntityIdMap.get(entityId);
        if (serviceProviderMetadata == null) {
            throw new TechnicalException("Service provider metadata resolver not found for entity id: %s", entityId);
        }
        return serviceProviderMetadata;
    }
}
