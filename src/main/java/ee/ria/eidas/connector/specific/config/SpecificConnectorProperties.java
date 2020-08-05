package ee.ria.eidas.connector.specific.config;

import com.google.common.collect.ImmutableMap;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.util.List;

@ConfigurationProperties(prefix = "eidas.connector")
@Getter
@Validated
@AllArgsConstructor
@ConstructorBinding
public class SpecificConnectorProperties {

    @NotEmpty
    private final String appInstanceId;

    @NotEmpty
    private final String specificConnectorRequestUrl;

    @Valid
    private final CacheProperties communicationCache;

    @Valid
    private final Metadata metadata;

    private final List<@Valid ServiceProvider> serviceProviders;

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class ServiceProvider {

        @NotEmpty
        private final String id;

        @NotEmpty
        @Pattern(regexp = "^https://.*$", message = "must use https protocol")
        private final String entityId;

        @NotEmpty
        private final String publicKey;

        @NotEmpty
        @Pattern(regexp = "^(public|private)$", message = "invalid Service Provider type")
        private final String type;
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class Metadata {

        @NotEmpty
        private final String keyStore;

        @NotEmpty
        private final String keyStorePassword;

        @NotEmpty
        private final String keyAlias;

        @NotEmpty
        private final String keyPassword;

        @NotEmpty
        private final String entityId;

        @Pattern(regexp = "^(public|private)$", message = "invalid Service Provider type")
        private final String spType;

        @NotEmpty
        private final String ssoServiceUrl;

        @NotNull
        private final Integer validityInDays;

        @NotNull
        @Size(min = 1)
        private final List<@NotEmpty String> digestMethods;

        @NotNull
        @Size(min = 1)
        private final List<@NotEmpty String> signingMethods;

        private final List<@Pattern(regexp = "^[A-Z]{2}$") String> supportedMemberStates;

        @Valid
        private final List<Attributes> attributes;

        private final String signatureAlgorithm;

        @Valid
        private final Organization organization;

        @Valid
        private final Contact supportContact;

        @Valid
        private final Contact technicalContact;

        public String getSignatureAlgorithm() {
            return signatureAlgorithm == null ? SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512 : signatureAlgorithm;
        }

        public String getSpType() {
            return spType == null ? "public" : spType;
        }
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class Attributes {

        @NotEmpty
        private final String name;

        @NotEmpty
        private final String friendlyName;
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class Organization {

        @NotEmpty
        private final String name;

        @NotEmpty
        private final String displayName;

        @NotEmpty
        private final String url;
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class Contact {

        @NotEmpty
        private final String surname;

        @NotEmpty
        private final String givenName;

        @NotEmpty
        private final String company;

        @NotEmpty
        private final String phone;

        @Email
        @NotEmpty
        private final String email;
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class CacheProperties {
        public static final String INCOMING_NODE_REQUESTS_CACHE = "incoming-node-requests-cache";
        public static final String OUTGOING_NODE_RESPONSES_CACHE = "outgoing-node-responses-cache";
        public static final String SP_REQUEST_CORRELATION_CACHE = "sp-request-correlation-cache";

        private static final ImmutableMap<String, String> cacheNameMapping = ImmutableMap.<String, String>builder()
                .put(INCOMING_NODE_REQUESTS_CACHE, "specificNodeConnectorRequestCache")
                .put(OUTGOING_NODE_RESPONSES_CACHE, "nodeSpecificConnectorResponseCache")
                .put(SP_REQUEST_CORRELATION_CACHE, "specificMSSpRequestCorrelationMap")
                .build();

        @NotNull
        private final String igniteConfigurationFileLocation;
        private final String igniteConfigurationBeanName;

        public static String getCacheName(String cacheName) {
            Assert.isTrue(cacheNameMapping.containsKey(cacheName), "Cache name mapping is required for " + cacheName + "!");
            return cacheNameMapping.get(cacheName);
        }

        public String getIgniteConfigurationBeanName() {
            return igniteConfigurationBeanName == null ? "igniteSpecificCommunication.cfg" : igniteConfigurationBeanName;
        }
    }
}
