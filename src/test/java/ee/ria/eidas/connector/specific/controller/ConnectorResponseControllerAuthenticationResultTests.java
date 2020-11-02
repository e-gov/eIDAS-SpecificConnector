package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataSigner;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import ee.ria.eidas.connector.specific.util.TestUtils;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.light.impl.ResponseStatus;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.net.URLBuilder;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.Assertions;
import org.joda.time.DateTime;
import org.junit.jupiter.api.*;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.ResponseImpl;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.cache.Cache;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import static ee.ria.eidas.connector.specific.util.TestUtils.SECURE_RANDOM_REGEX;
import static eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec.Definitions.*;
import static io.restassured.RestAssured.given;
import static java.lang.Math.toIntExact;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.hamcrest.text.MatchesPattern.matchesPattern;
import static org.joda.time.DateTimeZone.UTC;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.opensaml.saml.common.SAMLVersion.VERSION_20;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.util.ResourceUtils.getFile;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false,
        properties = {
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.service-providers[0].id=service-provider",
                "eidas.connector.service-providers[0].entity-id=https://localhost:8888/metadata",
                "eidas.connector.service-providers[0].key-alias=service-provider-metadata-signing",
                "eidas.connector.service-providers[0].type=public"
        })
public class ConnectorResponseControllerAuthenticationResultTests extends SpecificConnectorTest {

    public static final String RESPONDER_METADATA_URL = "https://localhost:8443/SpecificConnector/ConnectorResponderMetadata";
    public static final String SP_ASSERTIONS_URL = "https://localhost:8888/returnUrl";
    public static final String SP_METADATA_URL = "https://localhost:8888/metadata";
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

    @Autowired
    SpecificConnectorProperties connectorProperties;

    @Autowired
    LightRequestFactory lightRequestFactory;

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

    @TestFactory
    Stream<DynamicNode> successfulAuthentication() throws IOException, UnmarshallingException, XMLParserException {
        DateTime authenticationTime = new DateTime(UTC);
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(authnRequest, "LT", "", "public");
        ResponseStatus successfulAuthenticationStatus = ResponseStatus.builder()
                .statusMessage("urn:oasis:names:tc:SAML:2.0:status:Success")
                .statusCode("urn:oasis:names:tc:SAML:2.0:status:Success")
                .subStatusCode("urn:oasis:names:tc:SAML:2.0:status:AnySubStatusCode")
                .failure(false)
                .build();

        LightResponse lightResponse = createLightResponse(lightRequest, successfulAuthenticationStatus);
        ResponseStatus expectedStatus = lightResponse.getStatus();
        String levelOfAssurance = lightResponse.getLevelOfAssurance();

        Function<ResponseImpl, DynamicContainer> samlResponseTests = samlResponse -> {
            Status responseStatus = samlResponse.getStatus();
            return dynamicContainer("Redirected with valid SAML Response in location header",
                    of(
                            dynamicTest("Response version is SAML 2.0", () -> assertEquals(VERSION_20.toString(), samlResponse.getVersion().toString())),
                            dynamicTest("Is issued by Responder", () -> assertEquals(RESPONDER_METADATA_URL, samlResponse.getIssuer().getValue())),
                            dynamicTest("Is signed by Responder", () -> assertSignature(samlResponse)),
                            dynamicTest("Contains valid issuing time", () -> assertIssuingTime(samlResponse.getIssueInstant(), authenticationTime)),
                            dynamicTest("Id equals LightResponse id", () -> assertEquals(lightResponse.getId(), samlResponse.getID())),
                            dynamicTest("Contains valid reference to initial SAML AuthnRequest", () -> assertEquals(authnRequest.getID(), samlResponse.getInResponseTo())),
                            dynamicTest("Contains valid assertion consumer url", () -> assertEquals(SP_ASSERTIONS_URL, samlResponse.getDestination())),
                            dynamicTest("Contains status", () -> assertNotNull(responseStatus)),
                            dynamicContainer("Status is valid", assertResponseStatus(expectedStatus, responseStatus)),
                            dynamicTest("Contains no unencrypted assertions", () -> assertEquals(0, samlResponse.getAssertions().size())),
                            dynamicContainer("Contains valid encrypted assertion", assertEncryptedAssertions(samlResponse, levelOfAssurance, authenticationTime))
                    )
            );
        };

        return of("GET", "POST")
                .map(requestMethod -> dynamicContainer("Request method = " + requestMethod,
                        of(assertRedirectWithSAMLResponse(requestMethod, authnRequest, lightRequest, lightResponse))
                                .map(samlResponseTests)));
    }

    private void assertIssuingTime(DateTime issueInstant, DateTime authenticationTime) {
        assertNotNull(issueInstant);
        assertTrue(authenticationTime.isBefore(issueInstant));
    }

    @TestFactory
    Stream<DynamicNode> unsuccessfulAuthentication() throws IOException, UnmarshallingException, XMLParserException {
        DateTime authenticationTime = new DateTime(UTC);
        byte[] authnRequestXml = readFileToByteArray(getFile("classpath:__files/sp_authnrequests/sp-valid-request-signature.xml"));
        AuthnRequest authnRequest = OpenSAMLUtils.unmarshall(authnRequestXml, AuthnRequest.class);
        LightRequest lightRequest = lightRequestFactory.createLightRequest(authnRequest, "LT", "", "public");
        ResponseStatus unsuccessfulAuthenticationStatus = ResponseStatus.builder()
                .statusMessage("003002 - Authentication Failed.")
                .statusCode("urn:oasis:names:tc:SAML:2.0:status:Responder")
                .subStatusCode("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
                .failure(true)
                .build();
        LightResponse lightResponse = createLightResponse(lightRequest, unsuccessfulAuthenticationStatus);
        ResponseStatus expectedStatus = lightResponse.getStatus();

        Function<ResponseImpl, DynamicContainer> samlResponseTests = samlResponse -> {
            Status responseStatus = samlResponse.getStatus();
            return dynamicContainer("Redirected with valid SAML Error Response in location header",
                    of(
                            dynamicTest("Response version is SAML 2.0", () -> assertEquals(VERSION_20.toString(), samlResponse.getVersion().toString())),
                            dynamicTest("Is issued by Responder", () -> assertEquals(RESPONDER_METADATA_URL, samlResponse.getIssuer().getValue())),
                            dynamicTest("Is signed by Responder", () -> assertSignature(samlResponse)),
                            dynamicTest("Contains valid issuing time", () -> assertIssuingTime(samlResponse.getIssueInstant(), authenticationTime)),
                            dynamicTest("Contains id with valid format", () -> assertThat(samlResponse.getID(), matchesPattern(SECURE_RANDOM_REGEX))),
                            dynamicTest("Contains valid reference to initial SAML AuthnRequest", () -> assertEquals(authnRequest.getID(), samlResponse.getInResponseTo())),
                            dynamicTest("Contains valid assertion consumer url", () -> assertEquals(SP_ASSERTIONS_URL, samlResponse.getDestination())),
                            dynamicTest("Contains status", () -> assertNotNull(responseStatus)),
                            dynamicContainer("Status is valid", assertResponseStatus(expectedStatus, responseStatus)),
                            dynamicTest("Contains no unencrypted assertions", () -> assertEquals(0, samlResponse.getAssertions().size())),
                            dynamicTest("Contains no encrypted assertions", () -> assertEquals(0, samlResponse.getEncryptedAssertions().size()))
                    )
            );
        };

        return of("GET", "POST")
                .map(requestMethod -> dynamicContainer("Request method = " + requestMethod,
                        of(assertRedirectWithSAMLResponse(requestMethod, authnRequest, lightRequest, lightResponse))
                                .map(samlResponseTests)));
    }

    @SneakyThrows
    ResponseImpl assertRedirectWithSAMLResponse(String requestMethod, AuthnRequest authnRequest, LightRequest lightRequest, LightResponse lightResponse) {
        specificConnectorCommunication.putRequestCorrelation(lightRequest.getId(), authnRequest);
        BinaryLightToken binaryLightToken = putLightResponseToEidasNodeCommunicationCache(lightResponse);

        Response response = given()
                .param("token", BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken))
                .when()
                .request(requestMethod, "/ConnectorResponse")
                .then()
                .assertThat()
                .statusCode(requestMethod.equals("POST") ? 307 : 302)
                .header(HttpHeaders.LOCATION, startsWith("https://localhost:8888/returnUrl?SAMLResponse="))
                .extract().response();

        String samlResponseBase64 = new URLBuilder(response.getHeader(HttpHeaders.LOCATION)).getQueryParams().get(0).getSecond();
        return TestUtils.getResponse(samlResponseBase64);
    }

    void assertSignature(ResponseImpl response) throws SignatureException {
        responderMetadataSigner.validate(response.getSignature());
    }

    Stream<DynamicTest> assertResponseStatus(ResponseStatus expectedStatus, Status responseStatus) {
        String expectedMessage = expectedStatus.getStatusMessage();
        String expectedStatusCode = expectedStatus.getStatusCode();
        String expectedSubStatusCode = expectedStatus.getSubStatusCode();
        return of(
                dynamicTest("Contains status message: " + expectedMessage, () -> assertEquals(expectedMessage, responseStatus.getStatusMessage().getMessage())),
                dynamicTest("Contains status code: " + expectedStatusCode, () -> assertEquals(expectedStatusCode, responseStatus.getStatusCode().getValue())),
                dynamicTest("Contains sub status code: " + expectedSubStatusCode, () -> assertEquals(expectedSubStatusCode, responseStatus.getStatusCode().getStatusCode().getValue()))
        );
    }

    Stream<DynamicTest> assertEncryptedAssertions(ResponseImpl response, String levelOfAssurance, DateTime authenticationTime) {
        DateTime responseIssueInstant = response.getIssueInstant();
        List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
        assertNotNull(encryptedAssertions);
        assertEquals(1, encryptedAssertions.size());
        EncryptedAssertion encryptedAssertion = encryptedAssertions.get(0);
        Assertion assertion = decryptAssertion(encryptedAssertion);

        return of(
                dynamicTest("Is issued by Responder", () -> assertIssuer(assertion)),
                dynamicTest("Is signed by Responder", () -> assertSignature(assertion)),
                dynamicTest("Contains valid issuing time", () -> asseertIssueInstant(assertion, responseIssueInstant, authenticationTime)),
                dynamicTest("Contains valid assertion subject", () -> assertSubject(assertion, responseIssueInstant, authenticationTime)),
                dynamicTest("Contains valid assertion conditions", () -> assertConditions(assertion, responseIssueInstant, authenticationTime)),
                dynamicTest("Contains valid assertion audience restrictions", () -> assertAudienceRestriction(assertion)),
                dynamicTest("Contains valid Level of Assurance", () -> assertAuthnStatements(assertion, responseIssueInstant, levelOfAssurance)),
                dynamicTest("Contains requested attributes", () -> assertRequestedAttributes(assertion))
        );
    }

    @SneakyThrows
    void assertSignature(Assertion assertion) {
        assertTrue(assertion.isSigned());
        assertNotNull(assertion.getSignature());
        responderMetadataSigner.validate(assertion.getSignature());
    }

    void asseertIssueInstant(Assertion assertion, DateTime responseIssueInstant, DateTime authenticationTime) {
        assertNotNull(assertion.getIssueInstant());
        assertEquals(responseIssueInstant, assertion.getIssueInstant());
        assertTrue(authenticationTime.isBefore(assertion.getIssueInstant()));
    }

    void assertIssuer(Assertion assertion) {
        Issuer issuer = assertion.getIssuer();
        assertNotNull(issuer);
        assertNotNull(issuer.getValue());
        assertNotNull(issuer.getFormat());
        assertEquals(RESPONDER_METADATA_URL, issuer.getValue());
        assertEquals(issuer.getFormat(), NameIDType.ENTITY);
    }

    void assertSubject(Assertion assertion, DateTime responseIssueInstant, DateTime authenticationTime) {
        Subject subject = assertion.getSubject();
        assertNotNull(subject);
        assertSubjectNameId(subject.getNameID());
        assertSubjectConfirmation(subject.getSubjectConfirmations(), responseIssueInstant, authenticationTime);
    }

    void assertSubjectNameId(NameID nameID) {
        assertNotNull(nameID);
        List<String> validNameIDFormats = asList(NameIDType.UNSPECIFIED, NameIDType.TRANSIENT, NameIDType.PERSISTENT);
        assertTrue(validNameIDFormats.contains(nameID.getFormat()));
    }

    void assertSubjectConfirmation(List<SubjectConfirmation> subjectConfirmations, DateTime responseIssueInstant, DateTime authenticationTime) {
        assertNotNull(subjectConfirmations);
        assertEquals(1, subjectConfirmations.size());
        assertEquals(subjectConfirmations.get(0).getMethod(), SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmations.get(0).getSubjectConfirmationData();
        assertNotNull(subjectConfirmationData);
        assertRecipient(subjectConfirmationData);
        assertNotNull(subjectConfirmationData.getNotBefore());
        assertNotNull(subjectConfirmationData.getNotOnOrAfter());
        int assertionValidityInSeconds = toIntExact(connectorProperties.getResponderMetadata().getAssertionValidityInterval().getSeconds());
        assertTrue(authenticationTime.isBefore(subjectConfirmationData.getNotBefore()));
        assertTrue(responseIssueInstant.isEqual(subjectConfirmationData.getNotBefore()));
        assertTrue(responseIssueInstant.plusSeconds(assertionValidityInSeconds).isEqual(subjectConfirmationData.getNotOnOrAfter()));
    }

    void assertRecipient(SubjectConfirmationData subjectConfirmationData) {
        assertEquals(SP_ASSERTIONS_URL, subjectConfirmationData.getRecipient());
    }

    void assertRequestedAttributes(Assertion assertion) {
        List<String> requestedAttributes = asList("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                "http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName");
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        assertNotNull(attributeStatements);
        assertEquals(1, attributeStatements.size());
        List<Attribute> attributes = attributeStatements.get(0).getAttributes();
        List<String> attributesInAssertion = attributes.stream().map(Attribute::getName).collect(toList());
        Assertions.assertThat(attributesInAssertion).containsExactlyInAnyOrderElementsOf(requestedAttributes);
    }

    void assertConditions(Assertion assertion, DateTime responseIssueInstant, DateTime authenticationTime) {
        Conditions conditions = assertion.getConditions();
        assertNotNull(conditions);
        assertNotNull(conditions.getConditions());
        assertEquals(1, conditions.getConditions().size());
        int assertionValidityInSeconds = toIntExact(connectorProperties.getResponderMetadata().getAssertionValidityInterval().getSeconds());
        assertTrue(authenticationTime.isBefore(conditions.getNotBefore()));
        assertTrue(responseIssueInstant.isEqual(conditions.getNotBefore()));
        assertTrue(responseIssueInstant.plusSeconds(assertionValidityInSeconds).isEqual(conditions.getNotOnOrAfter()));
    }

    void assertAudienceRestriction(Assertion assertion) {
        Conditions conditions = assertion.getConditions();
        assertNotNull(conditions.getConditions());
        assertEquals(1, conditions.getConditions().size());
        assertEquals(1, conditions.getAudienceRestrictions().size());
        assertAudiences(conditions.getAudienceRestrictions().get(0).getAudiences());
    }

    void assertAudiences(List<Audience> audiences) {
        assertNotNull(audiences);
        assertNotEquals(0, audiences.size());
        audiences.forEach(audience -> assertEquals(SP_METADATA_URL, audience.getAudienceURI()));
    }

    void assertAuthnStatements(Assertion assertion, DateTime responseIssueTime, String levelOfAssurance) {
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        assertNotNull(authnStatements);
        assertEquals(1, authnStatements.size());
        AuthnStatement authnStatement = authnStatements.get(0);
        DateTime authnInstant = authnStatement.getAuthnInstant();
        assertTrue(responseIssueTime.isEqual(authnInstant));
        assertNotNull(authnStatement.getAuthnContext());
        assertNotNull(authnStatement.getAuthnContext().getAuthnContextClassRef());
        assertEquals(levelOfAssurance, authnStatement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    @SneakyThrows
    BinaryLightToken putLightResponseToEidasNodeCommunicationCache(LightResponse lightResponse) {
        BinaryLightToken binaryLightToken = BinaryLightTokenHelper.createBinaryLightToken(lightTokenResponseIssuerName, lightTokenResponseSecret, lightTokenResponseAlgorithm);
        String tokenId = binaryLightToken.getToken().getId();
        String samlResponseXml = lightJAXBCodec.marshall(lightResponse);
        nodeSpecificConnectorResponseCache.put(tokenId, samlResponseXml);
        return binaryLightToken;
    }

    LightResponse createLightResponse(LightRequest lightRequest, ResponseStatus responseStatus) {
        ImmutableAttributeMap.Builder requestedAttributes = ImmutableAttributeMap.builder();
        requestedAttributes.put(PERSON_IDENTIFIER);
        requestedAttributes.put(CURRENT_FAMILY_NAME);
        requestedAttributes.put(CURRENT_GIVEN_NAME);
        requestedAttributes.put(PLACE_OF_BIRTH);
        return LightResponse.builder()
                .id("_7.t.B2GE0lkaDDkpvwZJfrdOLrKQqiINw.0XnzAEucYP7yO7WVBC_hR2kkQ-hwy")
                .inResponseToId(lightRequest.getId())
                .status(responseStatus)
                .subject("assertion_subject")
                .subjectNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                .levelOfAssurance("http://eidas.europa.eu/LoA/high")
                .issuer("https://eidas-specificconnector:8443/EidasNode/ConnectorMetadata")
                .attributes(requestedAttributes.build())
                .build();
    }

    @SneakyThrows
    Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(TestUtils.getServiceProviderEncryptionCredential());
        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);
        return decrypter.decrypt(encryptedAssertion);
    }
}