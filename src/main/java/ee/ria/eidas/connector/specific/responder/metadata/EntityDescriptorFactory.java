package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.RandomStringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdattr.impl.EntityAttributesBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;

import java.util.List;

import static ee.ria.eidas.connector.specific.responder.metadata.OrganizationContactFactory.createContacts;
import static ee.ria.eidas.connector.specific.responder.metadata.OrganizationContactFactory.createOrganization;
import static java.lang.Math.toIntExact;
import static java.util.stream.Collectors.toList;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EntityDescriptorFactory {
    private static final String NS_SAML_EXTENSIONS = "http://eidas.europa.eu/saml-extensions";
    private static final String REQUESTER_ID_ATTRIBUTE_NAME = "http://macedir.org/entity-category";
    private static final String REQUESTER_ID_ATTRIBUTE_VALUE = "http://eidas.europa.eu/entity-attributes/termsofaccess/requesterid";

    public static EntityDescriptor create(ResponderMetadata responderMetadata, Credential metadataSigningCredential) throws SecurityException {
        EntityDescriptor descriptor = OpenSAMLUtils.buildObject(EntityDescriptor.class);
        descriptor.setEntityID(responderMetadata.getEntityId());
        descriptor.setID(generateEntityDescriptorId());
        descriptor.setExtensions(createExtensions(responderMetadata));
        descriptor.getRoleDescriptors().add(IDPSSODescriptorFactory.create(responderMetadata, metadataSigningCredential));
        if (responderMetadata.getOrganization() != null) {
            descriptor.setOrganization(createOrganization(responderMetadata.getOrganization()));
        }
        descriptor.getContactPersons().addAll(createContacts(responderMetadata.getContacts()));
        int validityInterval = toIntExact(responderMetadata.getValidityInterval().getSeconds());
        descriptor.setValidUntil(DateTime.now().plusSeconds(validityInterval));
        return descriptor;
    }

    private static String generateEntityDescriptorId() {
        return "_".concat(RandomStringUtils.randomAlphanumeric(39)).toLowerCase();
    }

    private static Extensions createExtensions(ResponderMetadata responderMetadata) {
        Extensions eidasExtensions = OpenSAMLUtils.buildObject(Extensions.class);
        eidasExtensions.getNamespaceManager().registerAttributeName(DigestMethod.TYPE_NAME);
        eidasExtensions.getUnknownXMLObjects().add(createSupportedMemberStatesAttributes(responderMetadata));
        eidasExtensions.getUnknownXMLObjects().addAll(createDigestMethods(responderMetadata));
        eidasExtensions.getUnknownXMLObjects().addAll(createSigningMethods(responderMetadata));
        eidasExtensions.getUnknownXMLObjects().add(createEntityAttributes());
        return eidasExtensions;
    }

    private static XSAny createSupportedMemberStatesAttributes(ResponderMetadata responderMetadata) {
        XSAny supportedMemberStates = new XSAnyBuilder()
                .buildObject(NS_SAML_EXTENSIONS, "SupportedMemberStates", "ria");

        responderMetadata.getSupportedMemberStates().forEach(ms -> {
            XSAny supportedMemberState = new XSAnyBuilder()
                    .buildObject(NS_SAML_EXTENSIONS, "MemberState", "ria");
            supportedMemberState.setTextContent(ms);
            supportedMemberStates.getUnknownXMLObjects().add(supportedMemberState);
        });
        return supportedMemberStates;
    }

    private static List<DigestMethod> createDigestMethods(ResponderMetadata responderMetadata) {
        return responderMetadata.getDigestMethods().stream().map(digestMethod -> {
            DigestMethod dm = OpenSAMLUtils.buildObject(DigestMethod.class);
            dm.setAlgorithm(digestMethod);
            return dm;
        }).collect(toList());
    }

    private static List<SigningMethod> createSigningMethods(ResponderMetadata responderMetadata) {
        return responderMetadata.getSigningMethods().stream().map(signingMethod -> {
            SigningMethod sm = OpenSAMLUtils.buildObject(SigningMethod.class);
            sm.setAlgorithm(signingMethod.getName());
            sm.setMinKeySize(signingMethod.getMinKeySize());
            sm.setMaxKeySize(signingMethod.getMaxKeySize());
            return sm;
        }).collect(toList());
    }

    private static EntityAttributes createEntityAttributes() {
        EntityAttributes entityAttributes = new EntityAttributesBuilder().buildObject();
        Attribute attribute = createRequesterIdAttribute();
        entityAttributes.getAttributes().add(attribute);
        return entityAttributes;
    }

    private static Attribute createRequesterIdAttribute() {
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setName(REQUESTER_ID_ATTRIBUTE_NAME);
        attribute.setNameFormat(Attribute.URI_REFERENCE);

        XSAny attributeValue = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        attributeValue.setTextContent(REQUESTER_ID_ATTRIBUTE_VALUE);
        attribute.getAttributeValues().add(attributeValue);
        return attribute;
    }
}
