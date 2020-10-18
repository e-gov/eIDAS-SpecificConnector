package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.validation.SpELAssert;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.constraints.URL;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static java.util.stream.Collectors.toList;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
import static org.hibernate.validator.internal.util.CollectionHelper.asSet;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.*;

@Slf4j
@Data
@Validated
@ConfigurationProperties(prefix = "eidas.connector")
public class SpecificConnectorProperties {

    @NotEmpty
    private String appInstanceId;

    @NotEmpty
    @URL(protocol = "https")
    private String specificConnectorRequestUrl;

    @Valid
    @NotNull
    private ResponderMetadata responderMetadata;

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

        @NotEmpty
        @Pattern(regexp = "^(public|private)$", message = "Invalid Service Provider type")
        private String type = "public";
    }

    @Data
    public static class ResponderMetadata {

        @Getter(AccessLevel.NONE)
        public static List<AttributeRegistry> SUPPORTED_EIDAS_ATTRIBUTES = unmodifiableList(asList(NaturalPersonSpec.REGISTRY, LegalPersonSpec.REGISTRY));

        @Getter(AccessLevel.NONE)
        public static List<SupportedAttribute> DEFAULT_SUPPORTED_ATTRIBUTES = unmodifiableList(SUPPORTED_EIDAS_ATTRIBUTES.stream()
                .flatMap(registry -> registry.getAttributes().stream())
                .map(def -> new SupportedAttribute(def.getNameUri().toString(), def.getFriendlyName()))
                .collect(toList()));

        @Getter(AccessLevel.NONE)
        public static Set<String> DEFAULT_DIGEST_METHODS = unmodifiableSet(asSet("http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2001/04/xmlenc#sha512"));

        @Getter(AccessLevel.NONE)
        public static List<SigningMethod> DEFAULT_SIGNING_METHODS = unmodifiableList(asList(
                new SigningMethod(ALGO_ID_SIGNATURE_ECDSA_SHA512, 384, 384),
                new SigningMethod(ALGO_ID_SIGNATURE_ECDSA_SHA256, 384, 384),
                new SigningMethod(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, 4096, 4096)));

        @Getter(AccessLevel.NONE)
        public static Set<String> DEFAULT_SUPPORTED_BINDINGS = unmodifiableSet(asSet(SAMLConstants.SAML2_POST_BINDING_URI,
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

        @NotEmpty
        private String keyPassword;

        @NotEmpty
        private String entityId;

        @NotEmpty
        private String ssoServiceUrl;

        @Pattern(regexp = "^(urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified|urn:oasis:names:tc:SAML:2.0:nameid-format:transient|urn:oasis:names:tc:SAML:2.0:nameid-format:persistent)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat")
        private String nameIdFormat;

        @Pattern(regexp = "^(public|private)$", message = "Invalid Service Provider type")
        private String spType = "public";

        @NotEmpty
        private String signatureAlgorithm = ALGO_ID_SIGNATURE_RSA_SHA512;

        @NotNull
        @Min(value = 1)
        @Max(value = 365)
        private Integer validityInDays = 1;

        @Valid
        private Organization organization;

        private Set<@Pattern(regexp = "^(urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST|urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Binding") String> supportedBindings = DEFAULT_SUPPORTED_BINDINGS;

        private Set<@Pattern(regexp = "^[A-Z]{2}$") String> supportedMemberStates = emptySet(); // TODO: SP request country validation

        private List<@Valid Contact> contacts;

        @Size(min = 1)
        private Set<@NotEmpty String> digestMethods = DEFAULT_DIGEST_METHODS; // TODO: Not sure how its used. SP metadata validation?

        @Size(min = 1)
        private List<@Valid SigningMethod> signingMethods = DEFAULT_SIGNING_METHODS; // TODO: Not sure how its used. SP metadata validation?

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
    @SpELAssert(value = "@supportedAttributesRegistry.getByName(#this.name) != null", message = "eIDAS Attribute not supported", appliesTo = "name")
    @SpELAssert(value = "@supportedAttributesRegistry.getByFriendlyName(#this.friendlyName).size() == 1", message = "eIDAS Attribute not supported", appliesTo = "friendlyName")
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

        @NotEmpty
        private String surname;

        @NotEmpty
        private String givenName;

        @NotEmpty
        private String company;

        @NotEmpty
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

}
