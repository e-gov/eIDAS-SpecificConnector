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
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;

import java.util.List;

import static ee.ria.eidas.connector.specific.responder.metadata.OrganizationContactFactory.createContacts;
import static ee.ria.eidas.connector.specific.responder.metadata.OrganizationContactFactory.createOrganization;
import static java.util.stream.Collectors.toList;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EntityDescriptorFactory {
    private static final String NS_SAML_EXTENSIONS = "http://eidas.europa.eu/saml-extensions";

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
        descriptor.setValidUntil(DateTime.now().plusDays(responderMetadata.getValidityInDays()));
        return descriptor;
    }

    private static String generateEntityDescriptorId() {
        return "_".concat(RandomStringUtils.randomAlphanumeric(39)).toLowerCase();
    }

    private static Extensions createExtensions(ResponderMetadata responderMetadata) {
        Extensions eidasExtensions = OpenSAMLUtils.buildObject(Extensions.class);
        eidasExtensions.getNamespaceManager().registerAttributeName(DigestMethod.TYPE_NAME);
        eidasExtensions.getUnknownXMLObjects().add(createSpType(responderMetadata.getSpType()));
        eidasExtensions.getUnknownXMLObjects().add(createSupportedMemberStatesAttributes(responderMetadata));
        eidasExtensions.getUnknownXMLObjects().addAll(createDigestMethods(responderMetadata));
        eidasExtensions.getUnknownXMLObjects().addAll(createSigningMethods(responderMetadata));
        return eidasExtensions;
    }

    private static XSAny createSpType(String sp) {
        XSAny spType = new XSAnyBuilder().buildObject(NS_SAML_EXTENSIONS, "SPType", "eidas");
        spType.setTextContent(sp);
        return spType;
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
}
