package ee.ria.eidas.connector.specific.metadata.sp;

import ee.ria.eidas.connector.specific.exception.TechnicalException;

import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toMap;

public class ServiceProviderMetadataResolver {
    private final Map<String, ServiceProviderMetadata> spMetadataEntityIdMap;

    public ServiceProviderMetadataResolver(List<ServiceProviderMetadata> serviceProviders) {
        this.spMetadataEntityIdMap = serviceProviders.stream().collect(toMap(ServiceProviderMetadata::getEntityId, sp -> sp));
    }

    public ServiceProviderMetadata getByEntityId(String entityId) {
        ServiceProviderMetadata serviceProviderMetadata = spMetadataEntityIdMap.get(entityId);
        if (serviceProviderMetadata == null) {
            throw new TechnicalException("Metadata resolver not found for entity id: %s", entityId);
        }
        return serviceProviderMetadata;
    }
}
