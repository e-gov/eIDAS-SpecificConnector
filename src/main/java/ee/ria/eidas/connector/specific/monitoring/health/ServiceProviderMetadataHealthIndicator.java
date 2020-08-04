package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

@Slf4j
public class ServiceProviderMetadataHealthIndicator extends AbstractHealthIndicator {
    private final ServiceProviderMetadata serviceProviderMetadata;

    public ServiceProviderMetadataHealthIndicator(ServiceProviderMetadata serviceProviderMetadata) {
        super("Metadata health check failed for: " + serviceProviderMetadata.getEntityId());
        this.serviceProviderMetadata = serviceProviderMetadata;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        if (serviceProviderMetadata.isUpdatedAndValid()) {
            builder.up().build();
        } else {
            builder.down().build();
        }
    }
}
