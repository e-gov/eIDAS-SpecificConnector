package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.jupiter.api.Test;
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
                "eidas.connector.service-providers[0].type=public"
        })
public class ServiceProviderMetadataHealthIndicatorTests extends ApplicationHealthTest {
    public static final String ERROR_FILTERING_METADATA = "Error filtering metadata from https://localhost:8888/metadata";

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
    void healthStatusDownWhen_InvalidSPType() {
        updateServiceProviderMetadata("sp-invalid-sp-type.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "Invalid Service provider metadata SPType");
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
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "The content of element 'md:SPSSODescriptor' is not complete. " +
                        "One of '{\"urn:oasis:names:tc:SAML:2.0:metadata\":NameIDFormat, " +
                        "\"urn:oasis:names:tc:SAML:2.0:metadata\":AssertionConsumerService}' is expected.");
    }

    @Test
    void healthStatusDownWhen_MissingAssertionConsumerBinding() {
        updateServiceProviderMetadata("sp-missing-assertion-consumer-binding.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "Invalid Service Provider metadata assertion consumer service binding");
    }

    @Test
    void healthStatusDownWhen_InvalidSchema() {
        updateServiceProviderMetadata("sp-invalid-schema.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
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
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "Invalid SPSSODescriptor certificate");
    }

    @Test
    void healthStatusDownWhen_ExpiredEncryptionCert() {
        updateServiceProviderMetadata("sp-expired-response-encryption-cert.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA, "Invalid SPSSODescriptor certificate");
    }

    private void assertServiceProviderMetadata(String errorMessage) {
        assertServiceProviderMetadata(errorMessage, null);
    }

    private void assertServiceProviderMetadata(String expectedExceptionMessage, String expectedCauseMessage) {
        ResolverException resolverException = assertThrows(ResolverException.class, () -> {
            serviceProviderMetadataRegistry.refreshMetadata(SP_ENTITY_ID);
        });
        mockSPMetadataServer.verify(1, getRequestedFor(urlEqualTo("/metadata")));
        assertThat(resolverException.getMessage(), containsString(expectedExceptionMessage));
        if (expectedCauseMessage != null) {
            assertThat(ExceptionUtils.getStackTrace(resolverException), containsString(expectedCauseMessage));
        }
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.SP_METADATA);
    }
}
