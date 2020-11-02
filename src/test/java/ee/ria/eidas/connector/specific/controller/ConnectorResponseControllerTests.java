package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.light.impl.ResponseStatus;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.cache.Cache;
import java.io.IOException;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static io.restassured.RestAssured.given;
import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public"
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
    SpecificConnectorCommunication specificConnectorCommunication;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

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
        specificMSSpRequestCorrelationMap.clear();
        nodeSpecificConnectorResponseCache.clear();
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
        LightResponse lightResponse = createLightResponse(authnRequest);
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

        assertTestLogs(INFO, "Get and remove AuthnRequest from cache with id: '_7fcff29db01783ec010f4dbb26c0bb35', Result: false");
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_IssuerNotFound(String requestMethod) throws IOException, UnmarshallingException, XMLParserException {
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        Issuer issuer = OpenSAMLUtils.buildObject(Issuer.class);
        issuer.setValue("https://localhost:1111/metadata");
        authnRequest.setIssuer(issuer);
        specificConnectorCommunication.putRequestCorrelation(authnRequest);

        LightResponse lightResponse = createLightResponse(authnRequest);
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
                .body("message", equalTo("Required String parameter 'token' is not present"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void badRequestWhen_InvalidParameterFormat_token(String requestMethod) {
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
    private LightResponse createLightResponse(AuthnRequest authnRequest) {
        ResponseStatus responseStatus = ResponseStatus.builder()
                .statusMessage("statusMessage")
                .statusCode("statusCode")
                .subStatusCode("subStatusCode")
                .failure(false)
                .build();

        LightResponse lightResponse = LightResponse.builder()
                .id("_7.t.B2GE0lkaDDkpvwZJfrdOLrKQqiINw.0XnzAEucYP7yO7WVBC_hR2kkQ-hwy")
                .inResponseToId(authnRequest.getID())
                .status(responseStatus)
                .subject("assertion_subject")
                .subjectNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                .levelOfAssurance("http://eidas.europa.eu/LoA/high")
                .issuer("https://eidas-specificconnector:8443/EidasNode/ConnectorMetadata")
                .build();
        return lightResponse;
    }
}