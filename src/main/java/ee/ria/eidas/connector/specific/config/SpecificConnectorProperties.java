package ee.ria.eidas.connector.specific.config;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.AbstractMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@ConfigurationProperties(prefix = "eidas.connector")
@Validated
@Data
public class SpecificConnectorProperties {

    @NotNull
    private String appInstanceId;

    @Valid
    private CacheProperties communicationCache = new CacheProperties();

    @Data
    @ToString
    public static class CacheProperties {

        public static final String INCOMING_NODE_REQUESTS_CACHE = "incoming-node-requests-cache";
        public static final String OUTGOING_NODE_RESPONSES_CACHE = "outgoing-node-responses-cache";

        private static Map<String, String> cacheNameMapping = Stream.of(
                new AbstractMap.SimpleEntry<>(INCOMING_NODE_REQUESTS_CACHE, "specificNodeConnectorRequestCache"),
                new AbstractMap.SimpleEntry<>(OUTGOING_NODE_RESPONSES_CACHE, "nodeSpecificConnectorResponseCache"))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        @NotNull
        private String igniteConfigurationFileLocation;

        private String igniteConfigurationBeanName = "igniteSpecificCommunication.cfg";

        public static String getCacheName(String cacheName) {
            Assert.isTrue(cacheNameMapping.containsKey(cacheName), "Cache name mapping is required for " + cacheName + "!");
            return cacheNameMapping.get(cacheName);
        }
    }
}
