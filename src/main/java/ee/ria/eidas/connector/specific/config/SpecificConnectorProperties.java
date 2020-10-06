package ee.ria.eidas.connector.specific.config;

import eu.eidas.auth.commons.protocol.eidas.spec.LegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.RepresentativeLegalPersonSpec;
import eu.eidas.auth.commons.protocol.eidas.spec.RepresentativeNaturalPersonSpec;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.*;
import java.security.KeyStore;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;
import static java.util.stream.Stream.of;
import static org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
import static org.hibernate.validator.internal.util.CollectionHelper.asSet;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.*;

@Slf4j
@ConfigurationProperties(prefix = "eidas.connector")
@Getter
@Validated
@AllArgsConstructor
@ConstructorBinding
public class SpecificConnectorProperties {

    @NotEmpty
    private final String appInstanceId;

    @NotEmpty
    @Pattern(regexp = "^https://.*$", message = "Must use https protocol")
    private final String specificConnectorRequestUrl;

    @Valid
    private final CacheProperties communicationCache;

    @Valid
    private final ResponderMetadata responderMetadata;

    private final List<@Valid ServiceProvider> serviceProviders;

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class ServiceProvider {

        @NotEmpty
        private final String id;

        @NotEmpty
        @Pattern(regexp = "^https://.*$", message = "Must use https protocol")
        private final String entityId;

        @NotEmpty
        private final String keyAlias;

        @NotEmpty
        @Pattern(regexp = "^(public|private)$", message = "Invalid Service Provider type")
        private final String type;
    }

    @Data
    public static class ResponderMetadata {

        public static final Set<SupportedAttribute> DEFAULT_SUPPORTED_ATTRIBUTES = unmodifiableSet(of(
                NaturalPersonSpec.Definitions.PERSON_IDENTIFIER,
                NaturalPersonSpec.Definitions.DATE_OF_BIRTH,
                NaturalPersonSpec.Definitions.CURRENT_FAMILY_NAME,
                NaturalPersonSpec.Definitions.CURRENT_GIVEN_NAME,
                RepresentativeNaturalPersonSpec.Definitions.PERSON_IDENTIFIER,
                RepresentativeNaturalPersonSpec.Definitions.DATE_OF_BIRTH,
                RepresentativeNaturalPersonSpec.Definitions.CURRENT_FAMILY_NAME,
                RepresentativeNaturalPersonSpec.Definitions.CURRENT_GIVEN_NAME,
                LegalPersonSpec.Definitions.LEGAL_PERSON_IDENTIFIER,
                LegalPersonSpec.Definitions.LEGAL_NAME,
                RepresentativeLegalPersonSpec.Definitions.LEGAL_PERSON_IDENTIFIER,
                RepresentativeLegalPersonSpec.Definitions.LEGAL_NAME)
                .map(def -> SupportedAttribute.builder().name(def.getNameUri().toString()).friendlyName(def.getFriendlyName()).build())
                .collect(toSet()));

        public static final Set<String> DEFAULT_DIGEST_METHODS = unmodifiableSet(asSet("http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512"));
        public static final Set<@Valid SigningMethod> DEFAULT_SIGNING_METHODS = unmodifiableSet(asSet(SigningMethod.builder().name(ALGO_ID_SIGNATURE_ECDSA_SHA512).minKeySize(384).maxKeySize(384).build(),
                SigningMethod.builder().name(ALGO_ID_SIGNATURE_ECDSA_SHA256).minKeySize(384).maxKeySize(384).build(),
                SigningMethod.builder().name(ALGO_ID_SIGNATURE_RSA_SHA256_MGF1).minKeySize(4096).maxKeySize(4096).build()));
        public static final Set<String> DEFAULT_SUPPORTED_BINDINGS = unmodifiableSet(asSet(SAMLConstants.SAML2_POST_BINDING_URI, SAMLConstants.SAML2_REDIRECT_BINDING_URI));

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

        private Set<@Pattern(regexp = "^(urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST|urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService/@Binding") String> supportedBindings = DEFAULT_SUPPORTED_BINDINGS;

        private Set<@Pattern(regexp = "^[A-Z]{2}$") String> supportedMemberStates = emptySet(); // TODO: SP request validation? SP metadata resolver chek?

        @Valid
        private Organization organization;

        private List<@Valid Contact> contacts;

        @Pattern(regexp = "^(urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified|urn:oasis:names:tc:SAML:2.0:nameid-format:transient|urn:oasis:names:tc:SAML:2.0:nameid-format:persistent)$",
                message = "Invalid md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat")
        private String nameIDFormat;

        @Pattern(regexp = "^(public|private)$", message = "Invalid Service Provider type")
        private String spType = "public";

        private String signatureAlgorithm = ALGO_ID_SIGNATURE_RSA_SHA512; // TODO: Not sure

        @NotNull
        @Min(value = 1)
        @Max(value = 365)
        private Integer validityInDays = 1;

        @Size(min = 1)
        private Set<@NotEmpty String> digestMethods = DEFAULT_DIGEST_METHODS; // TODO: Not sure how its used. SP metadata validation?

        @Size(min = 1)
        private Set<@Valid SigningMethod> signingMethods = DEFAULT_SIGNING_METHODS; // TODO: Not sure how its used. SP metadata validation?

        @Valid
        private Set<SupportedAttribute> supportedAttributes = DEFAULT_SUPPORTED_ATTRIBUTES;
    }

    @Builder
    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    @EqualsAndHashCode
    @ToString
    public static class SigningMethod {

        @NotEmpty
        private final String name;

        @NotNull
        private final Integer minKeySize;

        @NotNull
        private final Integer maxKeySize;
    }

    @Builder
    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    @EqualsAndHashCode
    @ToString
    public static class SupportedAttribute {

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

        @NotEmpty
        @Pattern(regexp = "^(technical|support|administrative|billing|other)$", message = "Invalid Contact type")
        private final String type;
    }

    @Getter
    @AllArgsConstructor
    @ConstructorBinding
    public static class CacheProperties {

        @NotNull
        private final String igniteConfigurationFileLocation;

        private final String igniteConfigurationBeanName = "igniteSpecificCommunication.cfg";

        @Getter
        @RequiredArgsConstructor
        public enum CacheNames {
            INCOMING_NODE_REQUESTS_CACHE("specificNodeConnectorRequestCache"),
            OUTGOING_NODE_RESPONSES_CACHE("nodeSpecificConnectorResponseCache"),
            SP_REQUEST_CORRELATION_CACHE("specificMSSpRequestCorrelationMap");
            private final String name;
        }
    }
}
