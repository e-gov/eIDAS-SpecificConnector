package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.HttpHeaders;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import javax.cache.Cache;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Iterator;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.eidas.connector.specific.exception.ResponseStatus.SP_ENCRYPTION_CERT_MISSING_OR_INVALID;
import static io.restassured.RestAssured.given;
import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
        })
class ConnectorResponseControllerTests extends SpecificConnectorTest {

    @Value("${lightToken.connector.response.issuer.name}")
    String lightTokenResponseIssuerName;

    @Value("${lightToken.connector.response.secret}")
    String lightTokenResponseSecret;

    @Value("${lightToken.connector.response.algorithm}")
    String lightTokenResponseAlgorithm;

    @Autowired
    @Qualifier("nodeSpecificConnectorResponseCache")
    Cache<String, String> nodeSpecificConnectorResponseCache;

    @Autowired
    @Qualifier("specificMSSpRequestCorrelationMap")
    Cache<String, String> specificMSSpRequestCorrelationMap;

    @Autowired
    @Qualifier("specificNodeConnectorRequestCache")
    Cache<String, String> specificNodeConnectorRequestCache;

    @Autowired
    SpecificConnectorCommunication specificConnectorCommunication;

    @Autowired
    EidasNodeCommunication eidasNodeCommunication;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

    @Autowired
    LightRequestFactory lightRequestFactory;

    @MockitoSpyBean
    ServiceProviderMetadataRegistry serviceProviderMetadataRegistry;

    @MockitoSpyBean
    ResponseFactory responseFactory;

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
        nodeSpecificConnectorResponseCache.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void samlErrorResponseWhen_ServiceProviderEncryptionCertificateNotFoundOrInvalid(String requestMethod) throws IOException, UnmarshallingException, XMLParserException, EncryptionException {
        BinaryLightToken binaryLightToken = prepareAuthnRequest();

        ServiceProviderMetadata mockSp = Mockito.mock(ServiceProviderMetadata.class);
        Mockito.doReturn(mockSp).when(serviceProviderMetadataRegistry).get("https://localhost:8888/metadata");
        Mockito.doReturn("https://localhost:8888/returnUrl").when(mockSp).getAssertionConsumerServiceUrl();
        Mockito.doThrow(new CertificateResolverException(UsageType.ENCRYPTION, "Metadata ENCRYPTION certificate missing or invalid")).when(mockSp).encrypt(any());

        String samlResponseBase64 = assertSAMLResponseParameter(requestMethod, binaryLightToken);
        Status status = TestUtils.getStatus(samlResponseBase64);
        assertEquals(SP_ENCRYPTION_CERT_MISSING_OR_INVALID.getStatusMessage(), status.getStatusMessage().getMessage());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Requester", status.getStatusCode().getValue());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:RequestDenied", status.getStatusCode().getStatusCode().getValue());
        assertSpecificNodeConnectorRequestCacheIsEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void internalServerErrorWhen_ExceptionInCreatingSAMLResponseObject(String requestMethod) throws IOException, UnmarshallingException, XMLParserException {
        BinaryLightToken binaryLightToken = prepareAuthnRequest();

        Mockito.doThrow(new TechnicalException("Unable to create SAML Response")).when(responseFactory).createSamlResponse(any(), any(), any());
        given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("Internal Server Error"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Something went wrong internally. Please consult server logs for further details."));

        assertSpecificNodeConnectorRequestCacheIsEmpty();
        assertTestLogs(ERROR, "Unable to create SAML Response");
    }

    private String assertSAMLResponseParameter(String requestMethod, BinaryLightToken binaryLightToken) throws MalformedURLException {
        Response response = given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .statusCode(requestMethod.equals("POST") ? 200 : 302)
                .extract().response();

        String samlResponse;
        if (requestMethod.equals("POST")) {
            samlResponse = response.xmlPath(XmlPath.CompatibilityMode.HTML).getString("**.findAll {it.@name == 'SAMLResponse'}.@value");
        } else {
            String location = response.getHeader(HttpHeaders.LOCATION);
            assertNotNull(location);
            URLBuilder urlBuilder = new URLBuilder(location);
            samlResponse = urlBuilder.getQueryParams().get(0).getSecond();
        }
        assertNotNull(samlResponse);
        return samlResponse;
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_MissingLightResponseForToken(String requestMethod) throws SpecificCommunicationException {
        BinaryLightToken binaryLightToken = BinaryLightTokenHelper.createBinaryLightToken(lightTokenResponseIssuerName, lightTokenResponseSecret, lightTokenResponseAlgorithm);
        given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Token is invalid or has expired"));

        assertTestLogs(INFO, format("Get and remove LightResponse from cache for tokenId: %s,  Result found: false", binaryLightToken.getToken().getId()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_MissingAuthnRequestForLightResponse(String requestMethod) throws IOException, UnmarshallingException, XMLParserException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "LV", "");

        LightResponse lightResponse = TestUtils.createLightResponse(lightRequest);
        BinaryLightToken binaryLightToken = putLightResponseToEidasNodeCommunicationCache(lightResponse);
        given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Authentication request related to token is invalid or has expired"));

        assertTestLogs(INFO, "Get and remove AuthnRequest from cache with correlation id: '5a968926a873fc52e65e6e87a2fbe0f7918cc0d18401ec3da366f2066a5c87ab07a497adffa521f16d3d7a0801d088819511c8f39beebb60a44b409851c64ca7', Result: false");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_IssuerNotFound(String requestMethod) throws IOException, UnmarshallingException, XMLParserException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        Issuer issuer = OpenSAMLUtils.buildObject(Issuer.class);
        issuer.setValue("https://localhost:1111/metadata");
        authnRequest.setIssuer(issuer);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);

        LightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "LV", "");
        specificConnectorCommunication.putAuthenticationRequest(lightRequest.getId(), signedAuthnRequest);
        LightResponse lightResponse = TestUtils.createLightResponse(lightRequest);
        BinaryLightToken binaryLightToken = putLightResponseToEidasNodeCommunicationCache(lightResponse);
        given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("SAML request is invalid - issuer not allowed"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_DuplicateRequiredParameter_token(String requestMethod) {
        given()
                .when()
                .param("token", RandomStringUtils.random(1000, true, true))
                .param("token", RandomStringUtils.random(1000, true, true))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Duplicate request parameter 'token'"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_MissingRequiredParameter_token(String requestMethod) {
        given()
                .when()
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Required request parameter 'token' for method parameter type String is not present"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterBase64Format_token(String requestMethod) {
        given()
                .when()
                .param("token", RandomStringUtils.random(999, true, true) + "!")
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.token: must match \"^[A-Za-z0-9+/=]{1,1000}$\"", requestMethod.toLowerCase())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterFormat_token(String requestMethod) {
        given()
                .when()
                .param("token", RandomStringUtils.random(100, true, true))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Token is invalid"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterSize_token(String requestMethod) {
        given()
                .when()
                .param("token", RandomStringUtils.random(1001, true, true))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo(format("%s.token: must match \"^[A-Za-z0-9+/=]{1,1000}$\"", requestMethod.toLowerCase())));
    }

    @TestFactory
    Stream<DynamicNode> internalServerErrorWhen_InvalidLightResponse() {
        return of("GET", "POST")
                .map(requestMethod -> dynamicContainer("requestMethod = " + requestMethod,
                        of("invalid-xml.xml",
                                "missing-id.xml",
                                "missing-issuer.xml",
                                "missing-in-response-to-id.xml",
                                "missing-status.xml",
                                "missing-attributes.xml")
                                .map(lightRequest -> dynamicTest("Using LightRequest from = " + lightRequest,
                                        () -> assertInternalServerErrorWhenInvalidLightResponse(requestMethod, lightRequest)))
                                .collect(toList())));
    }

    void assertInternalServerErrorWhenInvalidLightResponse(String requestMethod, String lightResponse) throws SpecificCommunicationException, IOException {
        BinaryLightToken binaryLightToken = BinaryLightTokenHelper.createBinaryLightToken(lightTokenResponseIssuerName, lightTokenResponseSecret, lightTokenResponseAlgorithm);
        String tokenId = binaryLightToken.getToken().getId();
        String authnRequestXml = readFileToString(getFile("classpath:__files/light_response/" + lightResponse));
        nodeSpecificConnectorResponseCache.put(tokenId, authnRequestXml);

        given()
                .when()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("Internal Server Error"))
                .body("incidentNumber", notNullValue())
                .body("message", equalTo("Something went wrong internally. Please consult server logs for further details."));

        assertTestLogs(ERROR, "Invalid LightResponse");
    }

    @NotNull
    @SneakyThrows
    private BinaryLightToken putLightResponseToEidasNodeCommunicationCache(LightResponse lightResponse) {
        BinaryLightToken binaryLightToken = BinaryLightTokenHelper.createBinaryLightToken(lightTokenResponseIssuerName, lightTokenResponseSecret, lightTokenResponseAlgorithm);
        String tokenId = binaryLightToken.getToken().getId();
        String samlResponseXml = lightJAXBCodec.marshall(lightResponse);
        nodeSpecificConnectorResponseCache.put(tokenId, samlResponseXml);
        return binaryLightToken;
    }

    @NotNull
    private BinaryLightToken prepareAuthnRequest() throws IOException, XMLParserException, UnmarshallingException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        AuthnRequest signedAuthnRequest = (AuthnRequest) TestUtils.getSignedSamlObject(authnRequest);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(signedAuthnRequest, "LT", "");
        specificConnectorCommunication.putAuthenticationRequest(lightRequest.getId(), signedAuthnRequest);
        LightResponse lightResponse = TestUtils.createLightResponse(lightRequest);
        return putLightResponseToEidasNodeCommunicationCache(lightResponse);
    }

    void assertSpecificNodeConnectorRequestCacheIsEmpty() {
        Iterator<Cache.Entry<String, String>> iterator = specificNodeConnectorRequestCache.iterator();
        assertFalse(iterator.hasNext());
    }
}
