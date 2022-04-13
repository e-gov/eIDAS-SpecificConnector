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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Optional;

import static ch.qos.logback.classic.Level.*;
import static ee.ria.eidas.connector.specific.monitoring.health.ResponderMetadataHealthIndicator.SIGNING_CERTIFICATE_EXPIRATION_WARNING;
import static java.lang.String.format;
import static java.time.Instant.now;
import static java.time.ZoneId.of;
import static java.time.temporal.ChronoUnit.MILLIS;
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.times;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@SpringBootTest(webEnvironment = RANDOM_PORT,
        properties = {
                "management.endpoints.web.exposure.exclude=",
                "management.endpoints.web.exposure.include=heartbeat"
        })
class ResponderMetadataHealthIndicatorTest extends ApplicationHealthTest {

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

    @BeforeEach
    void setup() {
        Mockito.doReturn(true).when(hsmProperties).isEnabled();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void healthStatusDownWhen_SigningCertificateExpired(boolean hsmEnabled) {
        Mockito.doReturn(hsmEnabled).when(hsmProperties).isEnabled();

        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotAfter().toInstant().plus(1, SECONDS);
        Mockito.doReturn(Clock.fixed(certificateExpiryTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();
        assertLogs(WARN, format("Responder metadata signing certificate '%s' with serial number '%s' is not valid. Validity period %s - %s",
                signingCredential.getEntityId(), x509.getSerialNumber().toString(), x509.getNotBefore().toInstant(), x509.getNotAfter().toInstant()));
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertWarnings(x509, warnings);
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void healthStatusDownWhen_SigningCertificateNotActive(boolean hsmEnabled) {
        Mockito.doReturn(hsmEnabled).when(hsmProperties).isEnabled();
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotBefore().toInstant().minus(1, SECONDS);
        Mockito.doReturn(Clock.fixed(certificateExpiryTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();
        assertLogs(WARN, format("Responder metadata signing certificate '%s' with serial number '%s' is not valid. Validity period %s - %s",
                signingCredential.getEntityId(), x509.getSerialNumber().toString(), x509.getNotBefore().toInstant(), x509.getNotAfter().toInstant()));
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void healthStatusUpWhen_ResponderMetadataGeneratorSigningCredentialRecovers() {
        Mockito.doAnswer(invocation -> {
            throw new SignatureException("Signing exception");
        }).when(signingCredential).getPrivateKey();
        TechnicalException technicalException = assertThrows(TechnicalException.class, () -> responderMetadataGenerator.createSignedMetadata());
        assertEquals("Unable to generate responder metadata", technicalException.getMessage());
        assertEquals("Signing exception", technicalException.getCause().getMessage());
        Response healthResponse = getHealthResponse();
        assertDependenciesDown(healthResponse, Dependencies.RESPONDER_METADATA);
        assertLogs(ERROR, "Signing with credential 'responder-metadata-sign' failed");
        Mockito.reset(signingCredential);
        responderMetadataGenerator.createSignedMetadata();
        healthResponse = getHealthResponse();
        assertLogs(INFO, "Signing with credential 'responder-metadata-sign' recovered");
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void healthStatusUpWhen_ResponseFactorySigningCredentialRecovers() throws IOException, UnmarshallingException, XMLParserException {
        Mockito.doAnswer(invocation -> {
            throw new SignatureException("Signing exception");
        }).when(signingCredential).getPrivateKey();
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        String expectedRelayState = RandomStringUtils.random(128, true, true);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "LT", expectedRelayState);
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
        assertLogs(ERROR, "Signing with credential 'responder-metadata-sign' failed");
        Mockito.reset(signingCredential);
        responseFactory.createSamlResponse(authnRequest, lightResponse, spMetadata);
        healthResponse = getHealthResponse();
        assertLogs(INFO, "Signing with credential 'responder-metadata-sign' recovered");
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void noCertificateWarningsWhen_WarningPeriodNotDue(boolean hsmEnabled) {
        Mockito.doReturn(hsmEnabled).when(hsmProperties).isEnabled();
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryTime = x509.getNotAfter().toInstant().minus(keyStoreExpirationWarningPeriod);
        Mockito.doReturn(Clock.fixed(certificateExpiryTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Response healthResponse = getHealthResponse();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void certificateExpiryWarningWhen_WarningPeriodDue(boolean hsmEnabled) {
        Mockito.doReturn(hsmEnabled).when(hsmProperties).isEnabled();
        X509Certificate x509 = signingCredential.getEntityCertificate();
        Instant certificateExpiryWarningTime = x509.getNotAfter().toInstant().minus(keyStoreExpirationWarningPeriod).plus(1, SECONDS);
        Mockito.doReturn(Clock.fixed(certificateExpiryWarningTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();

        Response healthResponse = getHealthResponse();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNotNull(warnings);
        assertWarnings(x509, warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void noSigningCredentialTestWhen_HsmDisabled() {
        Mockito.doReturn(false).when(hsmProperties).isEnabled();

        Instant lastHealthCheckTime = now();
        Instant lastHsmTestTime = lastHealthCheckTime.minus(responderMetadataHealthIndicator.getHsmTestInterval()).minus(1, MILLIS);
        Mockito.doReturn(Clock.fixed(lastHealthCheckTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Mockito.doReturn(lastHsmTestTime).when(responderMetadataHealthIndicator).getLastTestTime();

        Response healthResponse = getHealthResponse();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCertificateExpired();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCredentialInFailedState();
        Mockito.verify(responderMetadataHealthIndicator, times(0)).testSigningCredential();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void noSigningCredentialTestWhen_HsmEnabled_AndHsmCheckIntervalIsNotDue() {
        Instant lastHealthCheckTime = now();
        Instant lastHsmTestTime = lastHealthCheckTime.minus(responderMetadataHealthIndicator.getHsmTestInterval());
        Mockito.doReturn(Clock.fixed(lastHealthCheckTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Mockito.doReturn(lastHsmTestTime).when(responderMetadataHealthIndicator).getLastTestTime();

        Response healthResponse = getHealthResponse();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCertificateExpired();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCredentialInFailedState();
        Mockito.verify(responderMetadataHealthIndicator, times(0)).testSigningCredential();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
        assertDependenciesUp(healthResponse, Dependencies.RESPONDER_METADATA);
    }

    @Test
    void signingCredentialTestWhen_HsmEnabled_AndHsmCheckIntervalIsDue() {
        Instant lastHealthCheckTime = now();
        Instant lastHsmTestTime = lastHealthCheckTime.minus(responderMetadataHealthIndicator.getHsmTestInterval()).minus(1, MILLIS);
        Mockito.doReturn(Clock.fixed(lastHealthCheckTime, of("UTC"))).when(responderMetadataHealthIndicator).getSystemClock();
        Mockito.doReturn(lastHsmTestTime).when(responderMetadataHealthIndicator).getLastTestTime();

        Response healthResponse = getHealthResponse();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCertificateExpired();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).isSigningCredentialInFailedState();
        Mockito.verify(responderMetadataHealthIndicator, times(1)).testSigningCredential();
        List<String> warnings = healthResponse.jsonPath().getList("warnings");
        assertNull(warnings);
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
