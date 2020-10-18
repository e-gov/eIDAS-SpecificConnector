package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.OpenSAMLConfiguration;
import ee.ria.eidas.connector.specific.config.ResponderMetadataConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorConfiguration;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SigningMethod;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.w3c.dom.Node;

import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata.*;
import static java.lang.Integer.parseInt;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static net.shibboleth.utilities.java.support.xml.QNameSupport.constructQName;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {OpenSAMLConfiguration.class, SpecificConnectorConfiguration.class, ResponderMetadataConfiguration.class,
        ResponderMetadataGenerator.class, ResponderMetadataSigner.class}, initializers = SpecificConnectorTest.TestContextInitializer.class)
@TestPropertySource(value = "classpath:application-test.properties",
        properties = {
                "eidas.connector.responder-metadata.entity-id=https://localhost:9999/SpecificConnector/ConnectorResponderMetadata",
                "eidas.connector.responder-metadata.sso-service-url=https://localhost:9999/SpecificConnector/ServiceProvider",
                "eidas.connector.responder-metadata.name-id-format=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "eidas.connector.responder-metadata.sp-type=private",
                "eidas.connector.responder-metadata.validity-in-days=2",
                "eidas.connector.responder-metadata.supported-member-states=LV,LT",
                "eidas.connector.responder-metadata.signature-algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "eidas.connector.responder-metadata.contacts[0].surname=SupportSurName",
                "eidas.connector.responder-metadata.contacts[0].given-name=SupportGivenName",
                "eidas.connector.responder-metadata.contacts[0].company=SupportCompany",
                "eidas.connector.responder-metadata.contacts[0].phone=+372 111 1111",
                "eidas.connector.responder-metadata.contacts[0].email=support@ria.ee",
                "eidas.connector.responder-metadata.contacts[0].type=support",
                "eidas.connector.responder-metadata.contacts[1].surname=TechnicalSurName",
                "eidas.connector.responder-metadata.contacts[1].given-name=TechnicalGivenName",
                "eidas.connector.responder-metadata.contacts[1].company=TechnicalCompany",
                "eidas.connector.responder-metadata.contacts[1].phone=+372 222 2222",
                "eidas.connector.responder-metadata.contacts[1].email=technical@ria.ee",
                "eidas.connector.responder-metadata.contacts[1].type=technical",
                "eidas.connector.responder-metadata.organization.name=Estonian Information System Authority",
                "eidas.connector.responder-metadata.organization.display-name=RIA",
                "eidas.connector.responder-metadata.organization.url=https://www.ria.ee"
        })
class ResponderMetadataGeneratorTest {

    @Autowired
    ResponderMetadataGenerator responderMetadataGenerator;

    @Autowired
    ResponderMetadataSigner responderMetadataSigner;

    @Autowired
    AttributeRegistry supportedAttributesRegistry;

    @TestFactory
    Stream<DynamicNode> validResponderMetadata() {
        DateTime metadataRequestTime = DateTime.now();
        EntityDescriptor metadata = responderMetadataGenerator.createSignedMetadata();
        assertNotNull(metadata);
        Signature signature = metadata.getSignature();
        assertNotNull(signature);
        Extensions extensions = metadata.getExtensions();
        assertNotNull(extensions);
        IDPSSODescriptor idpSSODescriptor = metadata.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

        return of(
                dynamicTest("validUntil", () -> assertValidUntil(metadata, metadataRequestTime)),
                dynamicTest("validEntityId", () -> assertEntityId(metadata)),
                dynamicTest("validMetadataSigningCertificate", () -> assertMetadataSigningCertificate(signature)),
                dynamicTest("validMetadataSigningAlgorithm", () -> assertMetadataSigningAlgorithm(signature)),
                dynamicTest("validMetadataSignature", () -> assertMetadataSignature(signature)),
                dynamicTest("validRoleDescriptors", () -> assertValidRoleDescriptors(metadata)),
                dynamicTest("validOrganization", () -> assertOrganization(metadata)),
                dynamicTest("validContacts", () -> assertContacts(metadata)),
                dynamicContainer("validExtensions",
                        of(dynamicTest("validSpType", () -> assertSPType(extensions)),
                                dynamicTest("validSupportedMemberStates", () -> assertSupportedMemberStates(extensions)),
                                dynamicTest("validSupportedDigestMethods", () -> assertSupportedDigestMethods(extensions)),
                                dynamicTest("validSupportedSigningMethods", () -> assertSupportedSigningMethods(extensions)))),
                dynamicContainer("validIDPSSODescriptor",
                        of(dynamicTest("isWantAuthnRequestsSigned", () -> assertTrue(idpSSODescriptor.getWantAuthnRequestsSigned())),
                                dynamicTest("validNameIdFormat", () -> assertNameIdFormat(idpSSODescriptor)),
                                dynamicTest("validSupportedAttributes", () -> assertSupportedAttributes(idpSSODescriptor)),
                                dynamicTest("validSupportedProtocol", () -> assertSupportedProtocol(idpSSODescriptor)),
                                dynamicTest("validResponseSigningCertificate", () -> assertResponseSigningCertificate(idpSSODescriptor)),
                                dynamicTest("validSingleSignOnServiceBindings", () -> assertSingleSignOnServiceBindings(idpSSODescriptor))))
        );
    }

    private void assertContacts(EntityDescriptor metadata) {
        List<ContactPerson> contactPersons = metadata.getContactPersons();
        assertNotNull(contactPersons);
        assertEquals(2, contactPersons.size());

        ContactPerson supportContact = contactPersons.get(0);
        assertEquals("support", supportContact.getType().toString());
        assertEquals("SupportSurName", supportContact.getSurName().getName());
        assertEquals("SupportGivenName", supportContact.getGivenName().getName());
        assertEquals("SupportCompany", supportContact.getCompany().getName());
        assertEquals("support@ria.ee", supportContact.getEmailAddresses().get(0).getAddress());
        assertEquals("+372 111 1111", supportContact.getTelephoneNumbers().get(0).getNumber());

        ContactPerson technicalContact = contactPersons.get(1);
        assertEquals("technical", technicalContact.getType().toString());
        assertEquals("TechnicalSurName", technicalContact.getSurName().getName());
        assertEquals("TechnicalGivenName", technicalContact.getGivenName().getName());
        assertEquals("TechnicalCompany", technicalContact.getCompany().getName());
        assertEquals("technical@ria.ee", technicalContact.getEmailAddresses().get(0).getAddress());
        assertEquals("+372 222 2222", technicalContact.getTelephoneNumbers().get(0).getNumber());
    }

    private void assertOrganization(EntityDescriptor metadata) {
        Organization organization = metadata.getOrganization();
        assertNotNull(organization);
        assertEquals("Estonian Information System Authority", organization.getOrganizationNames().get(0).getValue());
        assertEquals("RIA", organization.getDisplayNames().get(0).getValue());
        assertEquals("https://www.ria.ee", organization.getURLs().get(0).getValue());
    }

    private void assertEntityId(EntityDescriptor metadata) {
        assertEquals("https://localhost:9999/SpecificConnector/ConnectorResponderMetadata", metadata.getEntityID());
    }

    private void assertValidUntil(EntityDescriptor metadata, DateTime metadataRequestTime) {
        assertEquals(48, Hours.hoursBetween(metadataRequestTime, metadata.getValidUntil()).getHours());
    }

    private void assertMetadataSigningCertificate(Signature signature) {
        assertNotNull(signature.getSigningCredential());
        assertNotNull(signature.getKeyInfo());
        X509Certificate signingCertificate = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        assertNotNull(signingCertificate);
        assertEquals(responderMetadataSigner.getSigningCredential(), signature.getSigningCredential());
    }

    private void assertMetadataSigningAlgorithm(Signature signature) {
        assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureAlgorithm());
    }

    private void assertMetadataSignature(Signature signature) throws SignatureException {
        responderMetadataSigner.validate(signature);
    }

    private void assertValidRoleDescriptors(EntityDescriptor entityDescriptor) {
        SPSSODescriptor spDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        assertNull(spDescriptor, "Responder metadata cannot contain SPSSODescriptor");
        IDPSSODescriptor idpSSODescriptor = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        assertNotNull(idpSSODescriptor);
    }

    private void assertNameIdFormat(IDPSSODescriptor idpSSODescriptor) {
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", idpSSODescriptor.getNameIDFormats().get(0).getFormat());
    }

    private void assertSupportedProtocol(IDPSSODescriptor idpSSODescriptor) {
        assertEquals(SAMLConstants.SAML20P_NS, idpSSODescriptor.getSupportedProtocols().get(0));
    }

    private void assertResponseSigningCertificate(IDPSSODescriptor idpSSODescriptor) throws CertificateEncodingException {
        List<KeyDescriptor> keyDescriptors = idpSSODescriptor.getKeyDescriptors();
        assertEquals(1, keyDescriptors.size());
        KeyDescriptor keyDescriptor = keyDescriptors.get(0);
        assertEquals(UsageType.SIGNING, keyDescriptor.getUse());
        X509Certificate signingCertificate = keyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        assertNotNull(signingCertificate);
        String responseSigningCertificate = signingCertificate.getValue();
        assertNotNull(responseSigningCertificate);
        byte[] expectedSigningCertificate = ((BasicX509Credential) responderMetadataSigner.getSigningCredential()).getEntityCertificate().getEncoded();
        assertArrayEquals(expectedSigningCertificate, Base64.decode(responseSigningCertificate));
    }

    private void assertSingleSignOnServiceBindings(IDPSSODescriptor idpSSODescriptor) {
        List<SingleSignOnService> singleSignOnServices = idpSSODescriptor.getSingleSignOnServices();
        List<String> ssoBindings = singleSignOnServices.stream().map(Endpoint::getBinding).collect(toList());
        assertThat(ssoBindings).containsExactlyInAnyOrderElementsOf(DEFAULT_SUPPORTED_BINDINGS);
        String ssoServiceUrl = "https://localhost:9999/SpecificConnector/ServiceProvider";
        assertThat(singleSignOnServices.stream().map(Endpoint::getLocation).collect(toList())).containsExactly(ssoServiceUrl, ssoServiceUrl);
    }

    private void assertSupportedAttributes(IDPSSODescriptor idpSSODescriptor) {
        List<SupportedAttribute> supportedAttributes = supportedAttributesRegistry.getAttributes().stream()
                .map(def -> new SupportedAttribute(def.getNameUri().toString(), def.getFriendlyName()))
                .collect(toList());
        List<SupportedAttribute> attributes = idpSSODescriptor.getAttributes().stream()
                .map(n -> new SupportedAttribute(n.getName(),
                        n.getFriendlyName())).collect(toList());
        assertThat(attributes).containsExactlyInAnyOrderElementsOf(supportedAttributes);
    }

    private void assertSPType(Extensions extensions) {
        List<XMLObject> xmlObjects = extensions.getUnknownXMLObjects(constructQName("http://eidas.europa.eu/saml-extensions", "SPType", "eias"));
        assertNotNull(xmlObjects);
        XMLObject spType = xmlObjects.get(0);
        assertNotNull(spType);
        assertNotNull(spType.getDOM());
        assertEquals("private", spType.getDOM().getTextContent());
    }

    private void assertSupportedMemberStates(Extensions extensions) {
        List<XMLObject> supportedMemberStatesXmlObjects = extensions.getUnknownXMLObjects(constructQName("http://eidas.europa.eu/saml-extensions", "SupportedMemberStates", "ria"));
        assertNotNull(supportedMemberStatesXmlObjects);
        XMLObject supportedMemberStatesXmlObject = supportedMemberStatesXmlObjects.get(0);
        assertNotNull(supportedMemberStatesXmlObject);
        List<XMLObject> memberStateXmlObjects = supportedMemberStatesXmlObject.getOrderedChildren();
        assertNotNull(memberStateXmlObjects);
        List<String> memberStates = memberStateXmlObjects.stream()
                .map(XMLObject::getDOM)
                .filter(Objects::nonNull)
                .map(Node::getTextContent).collect(toList());
        assertThat(memberStates).containsExactly("LV", "LT");
    }

    private void assertSupportedDigestMethods(Extensions extensions) {
        List<XMLObject> digestMethodXmlObjects = extensions.getUnknownXMLObjects(constructQName("urn:oasis:names:tc:SAML:metadata:algsupport", "DigestMethod", "alg"));
        assertNotNull(digestMethodXmlObjects);
        List<String> metadataDigestAlgorithms = digestMethodXmlObjects.stream()
                .map(XMLObject::getDOM)
                .filter(Objects::nonNull)
                .map(e -> e.getAttribute("Algorithm"))
                .collect(toList());

        assertThat(metadataDigestAlgorithms).containsExactlyInAnyOrderElementsOf(DEFAULT_DIGEST_METHODS);
    }

    private void assertSupportedSigningMethods(Extensions extensions) {
        List<XMLObject> signingMethodXmlObjects = extensions.getUnknownXMLObjects(constructQName("urn:oasis:names:tc:SAML:metadata:algsupport", "SigningMethod", "alg"));
        assertNotNull(signingMethodXmlObjects);
        List<SigningMethod> signingMethods = signingMethodXmlObjects.stream()
                .map(XMLObject::getDOM)
                .filter(Objects::nonNull)
                .map(e -> new SigningMethod(e.getAttribute("Algorithm"),
                        parseInt(e.getAttribute("MinKeySize")),
                        parseInt(e.getAttribute("MaxKeySize")))).collect(toList());
        assertThat(signingMethods).containsExactlyInAnyOrderElementsOf(DEFAULT_SIGNING_METHODS);
    }
}