package ee.ria.eidas.connector.specific.monitoring.health;

import com.github.tomakehurst.wiremock.client.CountMatchingStrategy;
import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
        })
public class ServiceProviderMetadataHealthIndicatorTests extends ApplicationHealthTest {
    public static final String ERROR_FILTERING_METADATA = "Error filtering metadata from https://localhost:8888/metadata";
    public static final String RESOLVER_EXCEPTION = "net.shibboleth.utilities.java.support.resolver.ResolverException: Unable to unmarshall metadata";

    @Autowired
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @Test
    void healthStatusUpWhen_ValidMetadata() throws ResolverException {
        updateServiceProviderMetadata("sp-valid-metadata.xml");
        serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        Response healthResponse = getHealthResponse();
        assertAllDependenciesUp(healthResponse);
    }

    @Test
    void healthStatusDownWhen_InvalidEntityId() {
        updateServiceProviderMetadata("sp-invalid-entity-id.xml");
        assertServiceProviderMetadata("Invalid Service provider metadata entityId");
    }

    @Test
    void healthStatusDownWhen_InvalidSignerCert() {
        updateServiceProviderMetadata("sp-invalid-signer-cert.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Signature trust establishment failed for metadata entry");
    }

    @Test
    void healthStatusDownWhen_InvalidSignature() {
        updateServiceProviderMetadata("sp-invalid-signature.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Signature trust establishment failed for metadata entry");
    }

    @Test
    void healthStatusDownWhen_ModifiedContent() {
        updateServiceProviderMetadata("sp-modified-content.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA);
        assertTestLogs(WARN, "Verification failed for URI \"#_hixqcccubh4zhy3k314yx8x2f6ucqyuyxz31cjb\"",
                "Expected Digest: jFuAdSyo/nKvMNUjksbhIqTCbds1qlArJjS5QGUasGvAsl66y08C8ZgkK94bheYd6Ovf6S7dgIfg",
                "Actual Digest: 1+C2BkDtXNgF4dB4FI2XzymY8kpRVmkXxRYV1J5Ctfs9lKBwvLBri3jnyJpRQG9VQ9erSa6kA9p/");
    }

    @Test
    void healthStatusDownWhen_InvalidNameIdFormat() {
        updateServiceProviderMetadata("sp-invalid-name-id-format.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Invalid Service Provider metadata NameIDFormat");
    }

    @Test
    void healthStatusDownWhen_MissingValidUntil() {
        updateServiceProviderMetadata("sp-missing-valid-until.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Metadata did not include a validUntil attribute");
    }

    @Test
    void healthStatusDownWhen_MissingAssertionConsumerService() {
        updateServiceProviderMetadata("sp-missing-assertion-consumer.xml");
        assertServiceProviderMetadata(RESOLVER_EXCEPTION,
                "The content of element 'md:SPSSODescriptor' is not complete. " +
                        "One of '{\"urn:oasis:names:tc:SAML:2.0:metadata\":NameIDFormat, " +
                        "\"urn:oasis:names:tc:SAML:2.0:metadata\":AssertionConsumerService}' is expected.");
    }

    @Test
    void healthStatusDownWhen_MissingAssertionConsumerBinding() {
        updateServiceProviderMetadata("sp-missing-assertion-consumer-binding.xml");
        assertServiceProviderMetadata(RESOLVER_EXCEPTION, "SAXParseException: cvc-complex-type.4: Attribute 'Binding' must appear on element 'md:AssertionConsumerService'.");
    }

    @Test
    void healthStatusDownWhen_InvalidSchema() {
        updateServiceProviderMetadata("sp-invalid-schema.xml");
        assertServiceProviderMetadata(RESOLVER_EXCEPTION,
                "Attribute 'Location' must appear on element 'md:AssertionConsumerService'");
    }

    @Test
    void healthStatusDownWhen_ExpiredMetadata() throws ResolverException {
        updateServiceProviderMetadata("sp-expired-valid-until.xml");
        serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        mockSPMetadataServer.verify(1, getRequestedFor(urlEqualTo("/metadata")));
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.SP_METADATA);
        assertLogs(WARN, "Metadata Resolver HTTPMetadataResolver service-provider: Entire metadata document from 'https://localhost:8888/metadata' was expired at time of loading, existing metadata retained");
        assertLogs(INFO, "Metadata Resolver HTTPMetadataResolver service-provider: Next refresh cycle for metadata provider 'https://localhost:8888/metadata' will occur on ");
    }

    @Test
    void healthStatusDownWhen_ExpiredSigningCert() {
        updateServiceProviderMetadata("sp-expired-request-signing-cert.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "CertificateExpiredException: NotAfter: Sat Aug 08 12:34:04 UTC 2020");
    }

    @Test
    void healthStatusDownWhen_ExpiredEncryptionCert() {
        updateServiceProviderMetadata("sp-expired-response-encryption-cert.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "CertificateExpiredException: NotAfter: Sat Aug 08 12:47:13 UTC 2020");
    }

    private void assertServiceProviderMetadata(String errorMessage) {
        assertServiceProviderMetadata(errorMessage, null);
    }

    private void assertServiceProviderMetadata(String expectedExceptionMessage, String expectedCauseMessage) {
        ResolverException resolverException = assertThrows(ResolverException.class, () -> {
            serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        });
        CountMatchingStrategy countStrategy = new CountMatchingStrategy(CountMatchingStrategy.GREATER_THAN_OR_EQUAL, 1);
        mockSPMetadataServer.verify(countStrategy, getRequestedFor(urlEqualTo("/metadata")));
        assertThat(resolverException.getMessage(), containsString(expectedExceptionMessage));
        if (expectedCauseMessage != null) {
            assertThat(ExceptionUtils.getRootCauseMessage(resolverException), containsString(expectedCauseMessage));
        }
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.SP_METADATA);
    }
}
