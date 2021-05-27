package ee.ria.eidas.connector.specific.monitoring.health;

import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.monitoring.ApplicationHealthTest;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataGenerator;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.light.impl.ResponseStatus;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.lang.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Optional;

import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static ee.ria.eidas.connector.specific.monitoring.health.ResponderMetadataHealthIndicator.SIGNING_CERTIFICATE_EXPIRATION_WARNING;
import static java.lang.String.format;
import static java.time.ZoneId.of;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
class ResponderMetadataHealthIndicatorTest extends ApplicationHealthTest {

    @SpyBean
    ResponderMetadataHealthIndicator responderMetadataHealthIndicator;

    @SpyBean
    BasicX509Credential signingCredential;

    @Autowired
    ResponderMetadataGenerator responderMetadataGenerator;

    @Autowired
    ResponseFactory responseFactory;

    @Autowired
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @Value("${eidas.connector.health.key-store-expiration-warning:30d}")
    Period keyStoreExpirationWarningPeriod;

    @Autowired
    LightRequestFactory lightRequestFactory;

    @AfterEach
    void cleanUp() {
        Mockito.reset(responderMetadataHealthIndicator, signingCredential);
    }

    @Test
    void healthStatusDownWhen_SigningCertificateExpired() {
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotAfter().toInstant().plus(1, SECONDS);
        Mockito.when(responderMetadataHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(certificateExpiryTime, of("UTC")));
        Response healthResponse = getHealthResponse();
        assertLogs(WARN, format("Responder metadata signing certificate '%s' with serial number '%s' is not valid. Validity period %s - %s",
                signingCredential.getEntityId(), x509.getSerialNumber().toString(), x509.getNotBefore().toInstant(), x509.getNotAfter().toInstant()));
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertWarnings(x509, warnings);
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void healthStatusDownWhen_SigningCertificateNotActive() {
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotBefore().toInstant().minus(1, SECONDS);
        Mockito.when(responderMetadataHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(certificateExpiryTime, of("UTC")));
        Response healthResponse = getHealthResponse();
        assertLogs(WARN, format("Responder metadata signing certificate '%s' with serial number '%s' is not valid. Validity period %s - %s",
                signingCredential.getEntityId(), x509.getSerialNumber().toString(), x509.getNotBefore().toInstant(), x509.getNotAfter().toInstant()));
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void healthStatusUpWhen_ResponderMetadataGeneratorSigningCredentialRecovers() {
        Mockito.when(signingCredential.getPrivateKey()).thenAnswer(invocation -> {
            throw new SignatureException("Signing exception");
        });
        TechnicalException technicalException = assertThrows(TechnicalException.class, () -> responderMetadataGenerator.createSignedMetadata());
        assertEquals("Unable to generate responder metadata", technicalException.getMessage());
        assertEquals("Signing exception", technicalException.getCause().getMessage());
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
        assertLogs(WARN, "Signing with credential 'responder-metadata-sign' failed");
        Mockito.reset(signingCredential);
        responderMetadataGenerator.createSignedMetadata();
        healthResponse = getHealthResponse();
        assertLogs(INFO, "Signing with credential 'responder-metadata-sign' recovered");
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void healthStatusUpWhen_ResponseFactorySigningCredentialRecovers() throws IOException, UnmarshallingException, XMLParserException {
        Mockito.when(signingCredential.getPrivateKey()).thenAnswer(invocation -> {
            throw new SignatureException("Signing exception");
        });
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        String expectedRelayState = RandomStringUtils.random(128, true, true);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(authnRequest, "LT", expectedRelayState, "public");
        ResponseStatus successfulAuthenticationStatus = ResponseStatus.builder()
                .statusMessage("urn:oasis:names:tc:SAML:2.0:status:Success")
                .statusCode("urn:oasis:names:tc:SAML:2.0:status:Success")
                .subStatusCode("urn:oasis:names:tc:SAML:2.0:status:AnySubStatusCode")
                .failure(false)
                .build();
        LightResponse lightResponse = TestUtils.createLightResponse(lightRequest, successfulAuthenticationStatus);
        ServiceProviderMetadata spMetadata = Mockito.mock(ServiceProviderMetadata.class);
        Mockito.doReturn("https://localhost:8888/metadata").when(spMetadata).getAssertionConsumerServiceUrl();
        TechnicalException technicalException = assertThrows(TechnicalException.class, () -> responseFactory.createSamlResponse(authnRequest, lightResponse, spMetadata));
        assertEquals("Unable to create SAML Response", technicalException.getMessage());
        assertEquals("Signing exception", technicalException.getCause().getMessage());
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
        assertLogs(WARN, "Signing with credential 'responder-metadata-sign' failed");
        Mockito.reset(signingCredential);
        responseFactory.createSamlResponse(authnRequest, lightResponse, spMetadata);
        healthResponse = getHealthResponse();
        assertLogs(INFO, "Signing with credential 'responder-metadata-sign' recovered");
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void noCertificateWarningsWhen_WarningPeriodNotDue() {
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotAfter().toInstant().minus(keyStoreExpirationWarningPeriod);
        Mockito.when(responderMetadataHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(certificateExpiryTime, of("UTC")));
        Response healthResponse = getHealthResponse();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void certificateExpiryWarningWhen_WarningPeriodDue() {
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryWarningTime = x509.getNotAfter().toInstant().minus(keyStoreExpirationWarningPeriod).plus(1, SECONDS);
        Mockito.when(responderMetadataHealthIndicator.getSystemClock()).thenReturn(Clock.fixed(certificateExpiryWarningTime, of("UTC")));
        Response healthResponse = getHealthResponse();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        assertWarnings(x509, warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    private void assertWarnings(X509Certificate x509, List<String> warnings) {
        Optional<String> signingCertificateWarning = warnings.stream()
                .filter(w -> w.contains(x509.getSerialNumber().toString()))
                .findFirst();
        assertTrue(signingCertificateWarning.isPresent());
        assertEquals(format(SIGNING_CERTIFICATE_EXPIRATION_WARNING,
                x509.getSubjectDN(),
                x509.getSerialNumber(),
                x509.getNotAfter().toInstant()), signingCertificateWarning.get());
    }
}