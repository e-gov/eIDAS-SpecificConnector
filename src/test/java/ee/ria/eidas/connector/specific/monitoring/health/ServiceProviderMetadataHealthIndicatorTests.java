package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

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
    public void healthStatusUpWhenValidMetadata() throws ResolverException {
        updateServiceProviderMetadata("valid-metadata.xml");
        serviceProviderMetadataResolver.getByEntityId(SP_ENTITY_ID).refreshMetadata();
        Response healthResponse = getHealthResponse();
        assertAllDependenciesUp(healthResponse);
    }

    @Test
    public void healthStatusDownWhenInvalidEntityId() {
        updateServiceProviderMetadata("invalid-entity-id.xml");
        assertServiceProviderMetadata("Invalid Service provider metadata entity id");
    }

    @Test
    public void healthStatusDownWhenInvalidSPType() {
        updateServiceProviderMetadata("invalid-sp-type.xml");
        assertServiceProviderMetadata("Invalid Service provider metadata SPType");
    }

    @Test
    public void healthStatusDownWhenInvalidSignerCert() {
        updateServiceProviderMetadata("invalid-signer-cert.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA);
    }

    @Test
    public void healthStatusDownWhenInvalidSignature() {
        updateServiceProviderMetadata("invalid-signature.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA);
    }

    @Test
    public void healthStatusDownWhenModifiedContent() {
        updateServiceProviderMetadata("modified-content.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA);
    }

    @Test
    public void healthStatusDownWhenMissingValidUntil() {
        updateServiceProviderMetadata("missing-valid-until.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Metadata did not include a validUntil attribute");
    }

    @Test
    public void healthStatusDownWhenMissingAssertionConsumerService() {
        updateServiceProviderMetadata("missing-assertion-consumer.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "The content of element 'md:SPSSODescriptor' is not complete. " +
                        "One of '{\"urn:oasis:names:tc:SAML:2.0:metadata\":NameIDFormat, " +
                        "\"urn:oasis:names:tc:SAML:2.0:metadata\":AssertionConsumerService}' is expected.");
    }

    @Test
    public void healthStatusDownWhenMissingAssertionConsumerBinding() {
        updateServiceProviderMetadata("missing-assertion-consumer-binding.xml");
        assertServiceProviderMetadata("Invalid Service Provider metadata assertion consumer service binding");
    }

    @Test
    public void healthStatusDownWhenInvalidSchema() {
        updateServiceProviderMetadata("invalid-schema.xml");
        assertServiceProviderMetadata(ERROR_FILTERING_METADATA,
                "Attribute 'Location' must appear on element 'md:AssertionConsumerService'");
    }

    @Test
    public void healthStatusDownWhenExpiredMetadata() throws ResolverException {
        updateServiceProviderMetadata("expired-valid-until.xml");
        serviceProviderMetadataResolver.getByEntityId(SP_ENTITY_ID).refreshMetadata();
        mockSPMetadataServer.verify(1, getRequestedFor(urlEqualTo("/metadata")));
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.SP_METADATA);
    }

    @Test
    public void healthStatusDownWhenExpiredSigningCert() {
        updateServiceProviderMetadata("expired-sp-signing-cert.xml");
        assertServiceProviderMetadata("Expired Service Provider metadata SPSSODescriptor certificate");
    }

    @Test
    public void healthStatusDownWhenExpiredEncryptionCert() {
        updateServiceProviderMetadata("expired-sp-encryption-cert.xml");
        assertServiceProviderMetadata("Expired Service Provider metadata SPSSODescriptor certificate");
    }

    private void assertServiceProviderMetadata(String errorMessage) {
        assertServiceProviderMetadata(errorMessage, null);
    }

    private void assertServiceProviderMetadata(String expectedExceptionMessage, String expectedCauseMessage) {
        ResolverException resolverException = assertThrows(ResolverException.class, () -> {
            serviceProviderMetadataResolver.getByEntityId(SP_ENTITY_ID).refreshMetadata();
        });
        mockSPMetadataServer.verify(1, getRequestedFor(urlEqualTo("/metadata")));
        assertThat(resolverException.getMessage(), containsString(expectedExceptionMessage));
        if (expectedCauseMessage != null) {
            assertThat(ExceptionUtils.getRootCauseMessage(resolverException), containsString(expectedCauseMessage));
        }
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.SP_METADATA);
    }
}
