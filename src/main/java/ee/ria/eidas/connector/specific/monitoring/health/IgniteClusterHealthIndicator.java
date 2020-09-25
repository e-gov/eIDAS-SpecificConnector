package ee.ria.eidas.connector.specific.monitoring.health;

import org.apache.ignite.Ignite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import javax.cache.Cache;
import java.util.UUID;

@Component
public class IgniteClusterHealthIndicator extends AbstractHealthIndicator {

    @Lazy
    @Autowired
    @Qualifier("igniteClient")
    private Ignite igniteInstance;

    @Lazy
    @Autowired
    @Qualifier("specificNodeConnectorRequestCache")
    private Cache<String, String> specificNodeConnectorRequestCache;

    @Lazy
    @Autowired
    @Qualifier("nodeSpecificConnectorResponseCache")
    private Cache<String, String> nodeSpecificConnectorResponseCache;

    @Lazy
    @Autowired
    @Qualifier("specificMSSpRequestCorrelationMap")
    private Cache<String, String> specificMSSpRequestCorrelationMap;

    public IgniteClusterHealthIndicator() {
        super("Ignite cluster health check failed");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        if (igniteInstance.cluster().active()
                && isCacheHealthy(specificNodeConnectorRequestCache)
                && isCacheHealthy(nodeSpecificConnectorResponseCache)
                && isCacheHealthy(specificMSSpRequestCorrelationMap)) {
            builder.up().build();
        } else {
            builder.down().build();
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private boolean isCacheHealthy(Cache cache) {
        String uuid = UUID.randomUUID().toString();
        cache.put(uuid, uuid);
        return uuid.equals(cache.getAndRemove(uuid));
    }
}
