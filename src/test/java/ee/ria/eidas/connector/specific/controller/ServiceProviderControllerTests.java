package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
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
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
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
import static org.junit.jupiter.api.Assertions.*;
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
                "eidas.connector.service-providers[0].type=public"
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
    void successfulWhen_ValidParameters(String requestMethod) throws IOException, SpecificCommunicationException, ParserConfigurationException, SAXException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64, "LV", relayState, "token");
        String binaryLightTokenId = BinaryLightTokenHelper.getBinaryLightTokenId(token, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        String lightRequest = specificNodeConnectorRequestCache.getAndRemove(binaryLightTokenId);
        assertNotNull(lightRequest);
        Element lightRequestXml = TestUtils.getXmlDocument(lightRequest);
        assertLightRequest(lightRequestXml, relayState);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void successfulWithGeneratedRelayStateWhen_ValidParametersAndNoRelayState(String requestMethod) throws IOException, SpecificCommunicationException, ParserConfigurationException, SAXException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64, "LV", relayState, "token");
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
    void badRequestWhen_InvalidSchema(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-schema-invalid-attribute.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - does not conform to schema"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidSignature(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-expired-request-signature.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - invalid signature"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void internalServerExceptionWhen_AuthenticationRequestReplay(String requestMethod) throws IOException, SpecificCommunicationException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        String relayState = RandomStringUtils.random(80, true, true);
        String token = assertReturnParameter(requestMethod, authnRequestBase64, "LV", relayState, "token");
        String binaryLightTokenId = BinaryLightTokenHelper.getBinaryLightTokenId(token, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        String lightRequest = specificNodeConnectorRequestCache.get(binaryLightTokenId);
        assertNotNull(lightRequest);

        given()
                .param("SAMLRequest", authnRequestBase64)
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
        assertNotNull(specificMSSpRequestCorrelationMap.getAndRemove("eafe0049c9fdc5317f3c369c058e6fc549689bc52b6359d0e79d0099614c6d35f9dfe199b8a2ab9d50a76763d4802cc6d6828b05a1b2ca8401899f1e0eb65310"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedSignatureMethod(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-unsupported-signature-method.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - invalid signature method"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ModifiedRequest(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-modified-request.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - invalid signature"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ValidSignature_InvalidIssuer(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-issuer-id.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - issuer not allowed"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_ValidSignature_InvalidAssertionConsumerUrl(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-invalid-assertion-consumer-url.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - invalid assertion consumer url"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void samlErrorResponseWhen_LevelOfAssurance_TooLow(String requestMethod) throws IOException, UnmarshallingException, XMLParserException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-level-of-assurance-too-low.xml");
        String samlResponseBase64 = assertReturnParameter(requestMethod, authnRequestBase64, "LV", "", "SAMLResponse");
        Status status = TestUtils.getStatus(samlResponseBase64);
        assertEquals("LoA is missing or invalid", status.getStatusMessage().getMessage());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Requester", status.getStatusCode().getValue());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:RequestDenied", status.getStatusCode().getStatusCode().getValue());

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void samlErrorResponseWhen_MetadataRequestSigningCertificateNotFoundOrInvalid(String requestMethod) throws IOException, UnmarshallingException, XMLParserException, SignatureException, ResolverException {
        ServiceProviderMetadata mockSp = Mockito.mock(ServiceProviderMetadata.class);
        Mockito.doReturn(mockSp).when(serviceProviderMetadataRegistry).get("https://localhost:8888/metadata");
        Mockito.doReturn("https://localhost:8888/returnUrl").when(mockSp).getAssertionConsumerServiceUrl();
        Mockito.doThrow(new CertificateResolverException(UsageType.SIGNING, "Metadata SIGNING certificate missing or invalid")).when(mockSp).validate(any());
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-level-of-assurance-too-low.xml");
        String samlResponseBase64 = assertReturnParameter(requestMethod, authnRequestBase64, "LV", "", "SAMLResponse");

        Status status = TestUtils.getStatus(samlResponseBase64);
        assertEquals(SP_SIGNING_CERT_MISSING_OR_INVALID.getStatusMessage(), status.getStatusMessage().getMessage());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Requester", status.getStatusCode().getValue());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:RequestDenied", status.getStatusCode().getStatusCode().getValue());
        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedCountry(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "FI")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - country not supported"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_NoRequestedAttributes(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-no-requested-attributes.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - no requested attributes"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_UnsupportedRequestedAttributes(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-unsupported-requested-attributes.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - unsupported requested attributes"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
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
                .body("message", equalTo("Required String parameter 'SAMLRequest' is not present"));

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
                .body("message", equalTo("Required String parameter 'country' is not present"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidSAMLRequestFormat(String requestMethod) {
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
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - does not conform to schema"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidAuthnRequest_MissingExtensions(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-missing-extensions.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "LV")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - no requested attributes"));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
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
    void badRequestWhen_InvalidParameterFormat_country(String requestMethod) throws IOException {
        String authnRequestBase64 = TestUtils.getAuthnRequestAsBase64("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml");
        given()
                .param("SAMLRequest", authnRequestBase64)
                .param("country", "FIN")
                .param("RelayState", RandomStringUtils.random(80, true, true))
                .when()
                .request(requestMethod, "/ServiceProvider")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.country: must match \"^[A-Z]{2}$\"", requestMethod.toLowerCase())));

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
                .param(duplicateParameterName, "XX")
                .param("country", "LV")
                .param("SAMLRequest", "c2FtbF9yZXF1ZXN0")
                .param("RelayState", "26a6aef8-12eb-11eb-adc1-0242ac120002")
                .when()
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
}