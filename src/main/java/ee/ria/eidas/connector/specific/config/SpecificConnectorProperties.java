package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.validation.SpELAssert;
import ee.ria.eidas.connector.specific.validation.ValidHsmConfiguration;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.URL;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;
import org.springframework.validation.annotation.Validated;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static java.util.stream.Collectors.toList;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
import static org.hibernate.validator.internal.util.CollectionHelper.asSet;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512;

@Slf4j
@Data
@Validated
@ValidHsmConfiguration
@ConfigurationProperties(prefix = "eidas.connector")
public class SpecificConnectorProperties {
    public static final String DEFAULT_CONTENT_SECURITY_POLICY = "block-all-mixed-content; default-src 'self'; object-src: 'none'; frame-ancestors 'none'; script-src 'self' 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='";

    @NotEmpty
    private String appInstanceId;

    @NotEmpty
    @URL(protocol = "https")
    private String specificConnectorRequestUrl;

    @Valid
    @NotNull
    private ResponderMetadata responderMetadata;

    private HsmProperties hsm = new HsmProperties();

    @SpELAssert(value = "new java.util.HashSet(#this.![id]).size() == #this.size()", message = "Service provider not unique", appliesTo = "id")
    @SpELAssert(value = "new java.util.HashSet(#this.![entityId]).size() == #this.size()", message = "Service provider not unique", appliesTo = "entityId")
    @SpELAssert(value = "new java.util.HashSet(#this.![keyAlias]).size() == #this.size()", message = "Service provider not unique", appliesTo = "keyAlias")
    private List<@Valid ServiceProvider> serviceProviders = new ArrayList<>();

    @NotNull
    @Min(value = 1000L)
    @Max(value = 31536000000L)
    private Long serviceProviderMetadataMinRefreshDelay = 60000L;

    @NotNull
    @Min(value = 60000L)
    @Max(value = 315360000000L)
    private Long serviceProviderMetadataMaxRefreshDelay = 14400000L;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    @DecimalMax(value = "1.0", inclusive = false)
    private BigDecimal serviceProviderMetadataRefreshDelayFactor = BigDecimal.valueOf(0.75);

    @Getter
    private boolean addSamlErrorAssertion;

    @NotEmpty
    private String contentSecurityPolicy = DEFAULT_CONTENT_SECURITY_POLICY;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ServiceProvider {

        @NotEmpty
        private String id;

        @NotEmpty
        @URL(protocol = "https")
        private String entityId;

        @NotEmpty
        private String keyAlias;
    }

    @Data
    @ConfigurationProperties(prefix = "eidas.connector.responder-metadata")
    public static class ResponderMetadata {

        @Getter(AccessLevel.NONE)
        public static final List<AttributeRegistry> SUPPORTED_EIDAS_ATTRIBUTES = unmodifiableList(asList(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY));

        @Getter(AccessLevel.NONE)
        public static final List<SupportedAttribute> DEFAULT_SUPPORTED_ATTRIBUTES = unmodifiableList(SUPPORTED_EIDAS_ATTRIBUTES.stream()
                .flatMap(registry -> registry.getAttributes().stream())
                .map(def -> new SupportedAttribute(def.getNameUri().toString(), def.getFriendlyName()))
                .collect(toList()));

        @Getter(AccessLevel.NONE)
        public static final Set<String> DEFAULT_DIGEST_METHODS = unmodifiableSet(asSet("http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmlenc#sha512"));

        @Getter(AccessLevel.NONE)
        public static final List<SigningMethod> DEFAULT_SIGNING_METHODS = unmodifiableList(asList(
                new SigningMethod(ALGO_ID_SIGNATURE_ECDSA_SHA512, 384, 384),
                new SigningMethod(ALGO_ID_SIGNATURE_ECDSA_SHA384, 384, 384),
                new SigningMethod(ALGO_ID_SIGNATURE_ECDSA_SHA256, 384, 384),
                new SigningMethod(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, 4096, 4096)));

        @Getter(AccessLevel.NONE)
        public static final Set<String> DEFAULT_SUPPORTED_BINDINGS = unmodifiableSet(asSet(SAMLConstants.SAML2_POST_BINDING_URI,
                SAMLConstants.SAML2_REDIRECT_BINDING_URI));

        @Pattern(regexp = "^/[a-zA-Z]+$", message = "Invalid responder metadata endpoint path")
        private String path;

        @NotEmpty
        private String trustStore;

        @NotEmpty
        private String trustStoreType = "PKCS12";

        @NotEmpty
        private String trustStorePassword;

        @NotEmpty
        private String keyStore;

        @NotEmpty
        private String keyStoreType = "PKCS12";

        @NotEmpty
        private String keyStorePassword;

        @NotEmpty
        private String keyAlias;

        private String keyPassword;

        @NotEmpty
        private String entityId;

        @NotEmpty
        private String ssoServiceUrl;

        @Pattern(regexp = "^(urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified|urn:oasis:names:tc:SAML:2.0:nameid-format:transient|urn:oasis:names:tc:SAML:2.0:nameid-format:persistent)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat")
        private String nameIdFormat;

        @NotEmpty
        private String signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;

        @NotEmpty
        private String keyTransportAlgorithm = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP;

        @NotEmpty
        private String encryptionAlgorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM;

        @NotNull
        @DurationUnit(ChronoUnit.DAYS)
        private Duration validityInterval = Duration.ofDays(1);

        @NotNull
        @DurationUnit(ChronoUnit.MINUTES)
        private Duration assertionValidityInterval = Duration.ofMinutes(5);

        @Valid
        private Organization organization;

        private Set<@Pattern(regexp = "^(urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST|urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Binding") String> supportedBindings = DEFAULT_SUPPORTED_BINDINGS;

        private Set<@Pattern(regexp = "^[A-Z]{2}$") String> supportedMemberStates = emptySet();

        private List<@Valid Contact> contacts;

        @Size(min = 1)
        private Set<@NotEmpty String> digestMethods = DEFAULT_DIGEST_METHODS;

        @Size(min = 1)
        private List<@Valid SigningMethod> signingMethods = DEFAULT_SIGNING_METHODS;

        private List<@Valid SupportedAttribute> supportedAttributes = DEFAULT_SUPPORTED_ATTRIBUTES;
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @SpELAssert(value = "#this.minKeySize <= #this.maxKeySize", message = "minKeySize <= maxKeySize", appliesTo = "minKeySize")
    public static class SigningMethod {

        @NotEmpty
        private String name;

        @NotNull
        private Integer minKeySize;

        @NotNull
        private Integer maxKeySize;
    }

    @Data
    @ToString
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @SpELAssert(value = "@eidasAttributesRegistry.getByName(#this.name) != null", message = "eIDAS Attribute not supported", appliesTo = "name")
    @SpELAssert(value = "@eidasAttributesRegistry.getByFriendlyName(#this.friendlyName).size() == 1", message = "eIDAS Attribute not supported", appliesTo = "friendlyName")
    public static class SupportedAttribute {

        @NotEmpty
        private String name;

        @NotEmpty
        private String friendlyName;
    }

    @Data
    public static class Organization {

        @NotEmpty
        private String name;

        @NotEmpty
        private String displayName;

        @NotEmpty
        private String url;
    }

    @Data
    public static class Contact {

        private String surname;

        private String givenName;

        private String company;

        private String phone;

        @Email
        @NotEmpty
        private String email;

        @NotEmpty
        @Pattern(regexp = "^(technical|support|administrative|billing|other)$", message = "Invalid Contact type")
        private String type;
    }

    @Getter
    @RequiredArgsConstructor
    public enum CacheNames {
        INCOMING_NODE_REQUESTS_CACHE("specificNodeConnectorRequestCache"),
        OUTGOING_NODE_RESPONSES_CACHE("nodeSpecificConnectorResponseCache"),
        SP_REQUEST_CORRELATION_CACHE("specificMSSpRequestCorrelationMap");
        private final String name;
    }

    @Data
    @ConfigurationProperties(prefix = "eidas.connector.hsm")
    public static class HsmProperties {

        private boolean enabled;

        private boolean certificatesFromHsm;

        private String pin;

        private String library;

        private String slot;

        @PositiveOrZero
        private Integer slotListIndex;

        @Override
        public String toString() {
            // The -- at the beginning of the return string is required in order to configure our PKCS11 security provider by using the HsmProperties defined here instead of a .cfg file
            if (slot != null) {
                return format("--name=eidas\nlibrary=%s\nslot=%s\n", library, slot);
            } else {
                return format("--name=eidas\nlibrary=%s\nslotListIndex=%s\n", library, slotListIndex);
            }
        }
    }
}
