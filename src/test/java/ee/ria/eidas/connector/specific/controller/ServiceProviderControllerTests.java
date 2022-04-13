package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.HttpHeaders;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.cache.Cache;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Iterator;
import java.util.stream.Stream;

import static ee.ria.eidas.connector.specific.exception.ResponseStatus.SP_SIGNING_CERT_MISSING_OR_INVALID;
import static ee.ria.eidas.connector.specific.util.TestUtils.SHA512_REGEX;
import static ee.ria.eidas.connector.specific.util.TestUtils.UUID_REGEX;
import static io.restassured.RestAssured.given;
import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.text.MatchesPattern.matchesPattern;
import static org.hamcrest.xml.HasXPath.hasXPath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
        })
class ServiceProviderControllerTests extends SpecificConnectorTest {

    @SpyBean
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @Autowired
    @Qualifier("specificNodeConnectorRequestCache")
    Cache<String, String> specificNodeConnectorRequestCache;

    @Autowired
    @Qualifier("specificMSSpRequestCorrelationMap")
    Cache<String, String> specificMSSpRequestCorrelationMap;

    @Value("${lightToken.connector.request.secret}")
    String lightTokenRequestSecret;

    @Value("${lightToken.connector.request.algorithm}")
    String lightTokenRequestAlgorithm;

    @BeforeAll
    static void startMetadataServers() {
        startServiceProviderMetadataServer();
    }

    @AfterAll
    static void stopMetadataServers() {
        mockSPMetadataServer.stop();
    }

    @AfterEach
    void cleanUp() {
        Mockito.reset(serviceProviderMetadataRegistry);
        specificMSSpRequestCorrelationMap.clear();
        specificNodeConnectorRequestCache.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void successfulWhen_ValidParameters(String requestMethod) throws UnmarshallingException, IOException, XMLParserException, SpecificCommunicationException, ParserConfigurationException, SAXException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64Signed, "LV", relayState, "token");
        String binaryLightTokenId = BinaryLightTokenHelper.getBinaryLightTokenId(token, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        String lightRequest = specificNodeConnectorRequestCache.getAndRemove(binaryLightTokenId);
        assertNotNull(lightRequest);
        Element lightRequestXml = TestUtils.getXmlDocument(lightRequest);
        assertLightRequest(lightRequestXml, relayState);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void successfulWithGeneratedRelayStateWhen_ValidParametersAndNoRelayState(String requestMethod) throws IOException, SpecificCommunicationException, ParserConfigurationException, SAXException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64Signed, "LV", relayState, "token");
        String binaryLightTokenId = BinaryLightTokenHelper.getBinaryLightTokenId(token, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        String lightRequest = specificNodeConnectorRequestCache.getAndRemove(binaryLightTokenId);
        assertNotNull(lightRequest);
        Element lightRequestXml = TestUtils.getXmlDocument(lightRequest);
        assertLightRequest(lightRequestXml, relayState);
    }

    private void assertLightRequest(Element lightRequestXml, String relayState) {
        assertThat(lightRequestXml, hasXPath("/lightRequest/id", matchesPattern(SHA512_REGEX)));
        if (relayState == null) {
            assertThat(lightRequestXml, hasXPath("/lightRequest/relayState", matchesPattern(UUID_REGEX)));
        } else {
            assertThat(lightRequestXml, hasXPath("/lightRequest/relayState", equalTo(relayState)));
        }
        assertThat(lightRequestXml, hasXPath("/lightRequest/citizenCountryCode", equalTo("LV")));
        assertThat(lightRequestXml, hasXPath("/lightRequest/issuer", equalTo("https://localhost:8888/metadata")));
        assertThat(lightRequestXml, hasXPath("/lightRequest/levelOfAssurance", equalTo("http://eidas.europa.eu/LoA/substantial")));
        assertThat(lightRequestXml, hasXPath("/lightRequest/nameIdFormat", equalTo("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")));
        assertThat(lightRequestXml, hasXPath("/lightRequest/spType", equalTo("public")));
        assertThat(lightRequestXml, hasXPath("/lightRequest/providerName", equalTo("eidas-eeserviceprovider")));
        assertThat(lightRequestXml, hasXPath("count(/lightRequest/requestedAttributes/attribute/definition)", equalTo("4")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void internalServerExceptionWhen_AuthenticationRequestReplay(String requestMethod) throws IOException, SpecificCommunicationException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64Signed, "LV", relayState, "token");
        String binaryLightTokenId = BinaryLightTokenHelper.getBinaryLightTokenId(token, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        String lightRequest = specificNodeConnectorRequestCache.get(binaryLightTokenId);
        assertNotNull(lightRequest);

        given()
                .param("SAMLRequest", authnRequestBase64Signed)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(500)
                .body("error", equalTo("Internal Server Error"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Something went wrong internally. Please consult server logs for further details."));

        assertNotNull(specificNodeConnectorRequestCache.getAndRemove(binaryLightTokenId));
        assertNotNull(specificMSSpRequestCorrelationMap.getAndRemove("5a968926a873fc52e65e6e87a2fbe0f7918cc0d18401ec3da366f2066a5c87ab07a497adffa521f16d3d7a0801d088819511c8f39beebb60a44b409851c64ca7"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void samlErrorResponseWhen_MetadataRequestSigningCertificateNotFoundOrInvalid(String requestMethod) throws IOException, UnmarshallingException, XMLParserException, SignatureException, ResolverException {
        ServiceProviderMetadata mockSp = Mockito.mock(ServiceProviderMetadata.class);
        Mockito.doReturn(mockSp).when(serviceProviderMetadataRegistry).get("https://localhost:8888/metadata");
        Mockito.doReturn("https://localhost:8888/returnUrl").when(mockSp).getAssertionConsumerServiceUrl();
        Mockito.doThrow(new CertificateResolverException(UsageType.SIGNING, "Metadata SIGNING certificate missing or invalid")).when(mockSp).validate(any());
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        String samlResponseBase64 = assertReturnParameter(requestMethod, authnRequestBase64Signed, "LV", "", "SAMLResponse");

        Status status = TestUtils.getStatus(samlResponseBase64);
        assertEquals(SP_SIGNING_CERT_MISSING_OR_INVALID.getStatusMessage(), status.getStatusMessage().getMessage());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Requester", status.getStatusCode().getValue());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:RequestDenied", status.getStatusCode().getStatusCode().getValue());
        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidSchema(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-schema-invalid-attribute.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - does not conform to schema", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidSignature(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-expired-request-signature.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid signature", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedSignatureMethod(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-unsupported-signature-method.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid signature method", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ModifiedRequest(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-modified-request.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid signature", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ValidSignature_InvalidIssuer(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-issuer-id.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - issuer not allowed", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ValidSignature_InvalidAssertionConsumerUrl(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-assertion-consumer-url.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid assertion consumer url", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedCountry(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - country not supported", "FI");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_NoRequestedAttributesElement(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-no-requested-attributes-element.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - no requested attributes", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_NoRequestedAttributes(String requestMethod) throws IOException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-no-requested-attributes.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        assertBadRequest(requestMethod, authnRequestBase64Signed, "SAML request is invalid - no requested attributes", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_NoRequesterId(String requestMethod) throws IOException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-no-requester-id.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        assertBadRequest(requestMethod, authnRequestBase64Signed, "SAML request is invalid - no RequesterID", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_NoSpType(String requestMethod) throws IOException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-no-sp-type.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        assertBadRequest(requestMethod, authnRequestBase64Signed, "SAML request is invalid - no SPType", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedRequestedAttributes(String requestMethod) throws IOException, XMLParserException, UnmarshallingException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-unsupported-requested-attributes.xml");
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshallAuthnRequest(authnRequestBase64);
        String authnRequestBase64Signed = TestUtils.getSignedSamlAsBase64(authnRequest);
        assertBadRequest(requestMethod, authnRequestBase64Signed, "SAML request is invalid - unsupported requested attributes", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_MissingRequiredParameter_SAMLRequest(String requestMethod) {
        given()
                .param("country", "LV")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Required request parameter 'SAMLRequest' for method parameter type String is not present"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_MissingRequiredParameter_country(String requestMethod) {
        given()
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Required request parameter 'country' for method parameter type String is not present"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidSAMLRequestFormat(String requestMethod) {
        given()
                .param("country", "LV")
                .param("SAMLRequest", "NonBASE64CharsÄÖÜÕ")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("errors", nullValue())
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.SAMLRequest: must match \"^[A-Za-z0-9+/=]+$\"", requestMethod.toLowerCase())));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidDecodedSAMLRequestFormat(String requestMethod) {
        given()
                .param("country", "LV")
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("errors", nullValue())
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - does not conform to schema"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @TestFactory
    Stream<DynamicNode> badRequestWhen_InvalidAuthnRequestSchema() {
        return of("GET", "POST")
                .map(requestMethod -> dynamicContainer("requestMethod = " + requestMethod,
                        of("sp-invalid-schema-invalid-attribute.xml",
                                "sp-invalid-schema-missing-signature.xml",
                                "sp-invalid-schema-missing-required-element.xml",
                                "sp-invalid-schema-multiple-elements.xml",
                                "sp-invalid-schema-sp-type.xml",
                                "sp-invalid-schema-invalid-requested-attribute.xml")
                                .map(authnRequest -> dynamicTest("AuthnRequest = " + authnRequest, () -> assertInvalidSAMLRequestSchema(requestMethod, authnRequest)))
                                .collect(toList())));
    }

    void assertInvalidSAMLRequestSchema(String requestMethod, String authnRequest) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/" + authnRequest);
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - does not conform to schema", "LV");
    }


    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_InvalidSAMLVersion(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-saml-version.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - expecting SAML Version to be 2.0", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingExtensions(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-extensions.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - no requested attributes", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingIssuer(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-issuer.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - missing issuer", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingID(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-id.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - does not conform to schema", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_ForceAuthn(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-force-authn.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - expecting ForceAuthn to be true", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingIssueInstant(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-issue-instant.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - does not conform to schema", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingRequestedAuthnContext(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-authn-context.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - missing RequestedAuthnContext", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingAuthnContextClassRef(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-authn-context-class-ref.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - does not conform to schema", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_InvalidLevelOfAssurance(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-loa.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid Level of Assurance", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_IsPassive(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-is-passive.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - expecting IsPassive to be false", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_NameIdFormat(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-name-id-format.xml");
        assertBadRequest(requestMethod, authnRequestBase64, "SAML request is invalid - invalid NameIDPolicy", "LV");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterFormat_country(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        assertBadRequest(requestMethod, authnRequestBase64, format("%s.country: must match \"^[A-Z]{2}$\"", requestMethod.toLowerCase()), "FIN");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterSize_RelayState(String requestMethod) {
        given()
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(81, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("errors", nullValue())
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.RelayState: must match \"^\\p{Print}{0,80}$\"", requestMethod.toLowerCase())));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterFormat_RelayState(String requestMethod) {
        given()
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .param("country", "LV")
                .param("RelayState", "ABC\tDEF")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("errors", nullValue())
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.RelayState: must match \"^\\p{Print}{0,80}$\"", requestMethod.toLowerCase())));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ParameterSize_SAMLRequest(String requestMethod) {
        given()
                .param("SAMLRequest", RandomStringUtils.random(131073, true, true))
                .param("country", "LV")
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("errors", nullValue())
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.SAMLRequest: size must be between 1 and 131072", requestMethod.toLowerCase())));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @TestFactory
    Stream<DynamicNode> badRequestWhen_DuplicateRequestParameter() {
        return of("GET", "POST")
                .map(requestMethod -> dynamicContainer("requestMethod = " + requestMethod,
                        of("SAMLRequest", "country", "RelayState")
                                .map(parameterName -> dynamicTest("Duplicate request parameter = " + parameterName, () -> assertDuplicateRequestParameter(requestMethod, parameterName)))
                                .collect(toList())));
    }

    @Nullable
    private String assertReturnParameter(String requestMethod, String authnRequestBase64, String country, String relayState, String parameterToReturn) throws MalformedURLException {
        Response response = given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", country)
                .param("RelayState", relayState)
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(requestMethod.equals("POST") ? 200 : 302)
                .extract().response();

        String parameterValue;
        if (requestMethod.equals("POST")) {
            parameterValue = response.xmlPath(XmlPath.CompatibilityMode.HTML).getString("**.findAll {it.@name == '" + parameterToReturn + "'}.@value");
        } else {
            String location = response.getHeader(HttpHeaders.LOCATION);
            assertNotNull(location);
            URLBuilder urlBuilder = new URLBuilder(location);
            parameterValue = urlBuilder.getQueryParams().get(0).getSecond();
        }
        assertNotNull(parameterValue);
        return parameterValue;
    }

    void assertDuplicateRequestParameter(String requestMethod, String duplicateParameterName) {
        given()
                .when()
                .param(duplicateParameterName, "XX")
                .param("country", "LV")
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .param("RelayState", "26a6aef8-12eb-11eb-adc1-0242ac120002")
                .request(requestMethod, "/ServiceProvider")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("Duplicate request parameter '%s'", duplicateParameterName)));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    void assertSpecificNodeConnectorRequestCacheIsEmpty() {
        Iterator<Cache.Entry<String, String>> iterator = specificNodeConnectorRequestCache.iterator();
        assertFalse(iterator.hasNext());
    }

    private void assertBadRequest(String requestMethod, String authnRequestBase64, String errorMessage, String lv) {
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", lv)
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(errorMessage));
        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }
}
