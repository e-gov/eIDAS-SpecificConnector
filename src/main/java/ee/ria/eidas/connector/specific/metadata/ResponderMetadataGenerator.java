package ee.ria.eidas.connector.specific.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.Metadata;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import lombok.SneakyThrows;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.lang.RandomStringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.saml.saml2.metadata.impl.ExtensionsBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Stream.of;
import static org.opensaml.saml.saml2.core.Attribute.URI_REFERENCE;
import static org.opensaml.saml.saml2.core.NameIDType.*;
import static org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration.SUPPORT;
import static org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration.TECHNICAL;
import static org.opensaml.security.credential.UsageType.SIGNING;

@Component
public class ResponderMetadataGenerator {

    public static final String NS_SAML_EXTENSIONS = "http://eidas.europa.eu/saml-extensions";
    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Autowired
    private MetadataSigner metadataSigner;

    @Autowired
    private Credential metadataSigningCredential;

    public String getMetadata() {
        try {
            return getXmlString(buildEntityDescriptor());
        } catch (Exception e) {
            throw new TechnicalException("Unable to generate metadata", e);
        }
    }

    private EntityDescriptor buildEntityDescriptor() throws MarshallingException, SecurityException, SignatureException {
        Metadata metadata = connectorProperties.getMetadata();
        EntityDescriptor descriptor = buildSAMLObject(EntityDescriptor.class);
        descriptor.setEntityID(metadata.getEntityId());
        descriptor.setValidUntil(DateTime.now().plusDays(metadata.getValidityInDays()));
        descriptor.setID(generateEntityDescriptorId());
        descriptor.setExtensions(generateExtensions());
        descriptor.getRoleDescriptors().add(buildIDPSSODescriptor());
        descriptor.setOrganization(buildOrganization());
        descriptor.getContactPersons().add(buildContact(SUPPORT, connectorProperties.getMetadata().getSupportContact()));
        descriptor.getContactPersons().add(buildContact(TECHNICAL, connectorProperties.getMetadata().getTechnicalContact()));
        metadataSigner.sign(descriptor);
        return descriptor;
    }

    private String generateEntityDescriptorId() {
        return "_".concat(RandomStringUtils.randomAlphanumeric(39)).toLowerCase();
    }

    private IDPSSODescriptor buildIDPSSODescriptor() throws SecurityException {
        IDPSSODescriptor idpDescriptor = buildSAMLObject(IDPSSODescriptor.class);
        idpDescriptor.setWantAuthnRequestsSigned(true);
        idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        idpDescriptor.getNameIDFormats().addAll(buildNameIDFormat());
        idpDescriptor.getKeyDescriptors().add(getKeyDescriptor());
        idpDescriptor.getSingleSignOnServices().addAll(buildSingleSignOnServicesBindingLocations());
        idpDescriptor.getAttributes().addAll(buildSupportedAttributes());
        return idpDescriptor;
    }

    private List<Attribute> buildSupportedAttributes() {
        return connectorProperties.getMetadata().getAttributes().stream().map(attribute -> {
            Attribute entityAttribute = buildSAMLObject(Attribute.class);
            entityAttribute.setName(attribute.getName());
            entityAttribute.setFriendlyName(attribute.getFriendlyName());
            entityAttribute.setNameFormat(URI_REFERENCE);
            return entityAttribute;
        }).collect(toList());
    }

    private List<SingleSignOnService> buildSingleSignOnServicesBindingLocations() {
        ArrayList<SingleSignOnService> singleSignOnServices = new ArrayList<>();
        String ssoServiceUrl = connectorProperties.getMetadata().getSsoServiceUrl();
        SingleSignOnService ssos = buildSAMLObject(SingleSignOnService.class);
        ssos.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        ssos.setLocation(ssoServiceUrl);
        singleSignOnServices.add(ssos);
        ssos = buildSAMLObject(SingleSignOnService.class);
        ssos.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        ssos.setLocation(ssoServiceUrl);
        singleSignOnServices.add(ssos);
        return singleSignOnServices;
    }

    private Collection<NameIDFormat> buildNameIDFormat() {
        return of(UNSPECIFIED, TRANSIENT, PERSISTENT).map(nameIdType -> {
            NameIDFormat unspecifiedNameID = buildSAMLObject(NameIDFormat.class);
            unspecifiedNameID.setFormat(nameIdType);
            return unspecifiedNameID;
        }).collect(toList());
    }

    private KeyDescriptor getKeyDescriptor() throws SecurityException {
        KeyDescriptor descriptor = buildSAMLObject(KeyDescriptor.class);
        descriptor.setUse(SIGNING);
        descriptor.setKeyInfo(getKeyInfoGenerator().generate(metadataSigningCredential));
        return descriptor;
    }

    private KeyInfoGenerator getKeyInfoGenerator() {
        NamedKeyInfoGeneratorManager generatorManager = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager();
        return generatorManager.getDefaultManager().getFactory(metadataSigningCredential).newInstance();
    }

    private Organization buildOrganization() {
        SpecificConnectorProperties.Organization organization = connectorProperties.getMetadata().getOrganization();
        Organization samlOrganization = buildSAMLObject(Organization.class);
        OrganizationDisplayName odn = buildSAMLObject(OrganizationDisplayName.class);
        odn.setValue(organization.getDisplayName());
        odn.setXMLLang("en");
        samlOrganization.getDisplayNames().add(odn);

        OrganizationName on = buildSAMLObject(OrganizationName.class);
        on.setValue(organization.getName());
        on.setXMLLang("en");
        samlOrganization.getOrganizationNames().add(on);

        OrganizationURL url = buildSAMLObject(OrganizationURL.class);
        url.setValue(organization.getUrl());
        url.setXMLLang("en");
        samlOrganization.getURLs().add(url);
        return samlOrganization;
    }

    private ContactPerson buildContact(ContactPersonTypeEnumeration contactType, SpecificConnectorProperties.Contact contact) {
        ContactPerson contactPerson = buildSAMLObject(ContactPerson.class);
        contactPerson.setType(contactType);

        EmailAddress emailAddress = buildSAMLObject(EmailAddress.class);
        emailAddress.setAddress(contact.getEmail());
        contactPerson.getEmailAddresses().add(emailAddress);

        Company company = buildSAMLObject(Company.class);
        company.setName(contact.getCompany());
        contactPerson.setCompany(company);

        GivenName givenName = buildSAMLObject(GivenName.class);
        givenName.setName(contact.getGivenName());
        contactPerson.setGivenName(givenName);

        SurName surName = buildSAMLObject(SurName.class);
        surName.setName(contact.getSurname());
        contactPerson.setSurName(surName);

        TelephoneNumber phoneNumber = buildSAMLObject(TelephoneNumber.class);
        phoneNumber.setNumber(contact.getPhone());
        contactPerson.getTelephoneNumbers().add(phoneNumber);
        return contactPerson;
    }


    private Extensions generateExtensions() {
        Extensions eidasExtensions = generateMetadataExtension();
        generateSpType(eidasExtensions);
        generateSupportedMemberStatesAttributes(eidasExtensions);
        generateDigestMethods(eidasExtensions);
        generateSigningMethods(eidasExtensions);
        return eidasExtensions;
    }

    private void generateSpType(Extensions eidasExtensions) {
        XSAny spType = new XSAnyBuilder().buildObject(NS_SAML_EXTENSIONS, "SPType", "eidas");
        spType.setTextContent(connectorProperties.getMetadata().getSpType());
        eidasExtensions.getUnknownXMLObjects().add(spType);
    }

    private void generateSupportedMemberStatesAttributes(Extensions eidasExtensions) {
        XSAny supportedMemberStates = new XSAnyBuilder().buildObject(NS_SAML_EXTENSIONS, "SupportedMemberStates", "ria");
        connectorProperties.getMetadata().getSupportedMemberStates().forEach(ms -> {
            XSAny supportedMemberState = new XSAnyBuilder().buildObject(NS_SAML_EXTENSIONS, "MemberState", "ria");
            supportedMemberState.setTextContent(ms);
            supportedMemberStates.getUnknownXMLObjects().add(supportedMemberState);
        });
        eidasExtensions.getUnknownXMLObjects().add(supportedMemberStates);
    }

    private void generateDigestMethods(Extensions eidasExtensions) {
        connectorProperties.getMetadata().getDigestMethods().forEach(digestMethod -> {
            DigestMethod dm = buildSAMLObject(DigestMethod.class);
            dm.setAlgorithm(digestMethod);
            eidasExtensions.getUnknownXMLObjects().add(dm);
        });
    }

    private void generateSigningMethods(Extensions eidasExtensions) {
        connectorProperties.getMetadata().getSigningMethods().forEach(digestMethod -> {
            SigningMethod dm = buildSAMLObject(SigningMethod.class);
            dm.setAlgorithm(digestMethod);
            eidasExtensions.getUnknownXMLObjects().add(dm);
        });
    }

    public static Extensions generateMetadataExtension() {
        ExtensionsBuilder extensionsBuilder = new ExtensionsBuilder();
        return extensionsBuilder.buildObject(SAMLConstants.SAML20MD_NS, "Extensions", "md");
    }

    @SneakyThrows
    private static <T extends SAMLObject> T buildSAMLObject(final Class<T> type) {
        QName defaultElementName = (QName) type.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        final SAMLObjectBuilder<T> builder = (SAMLObjectBuilder<T>) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .<T>getBuilderOrThrow(defaultElementName);
        return builder.buildObject();
    }

    public static String getXmlString(final XMLObject object) throws MarshallingException {
        Element entityDescriptorElement = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object).marshall(object);
        return SerializeSupport.nodeToString(entityDescriptorElement);
    }
}
