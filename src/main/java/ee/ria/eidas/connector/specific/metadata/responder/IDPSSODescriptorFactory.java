package ee.ria.eidas.connector.specific.metadata.responder;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata;
import ee.ria.eidas.connector.specific.saml.OpenSAMLUtils;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;

import java.util.ArrayList;
import java.util.List;

import static java.lang.Boolean.TRUE;
import static java.util.stream.Collectors.toList;
import static org.opensaml.saml.saml2.core.Attribute.URI_REFERENCE;
import static org.opensaml.security.credential.UsageType.SIGNING;

public class IDPSSODescriptorFactory {

    public static IDPSSODescriptor create(ResponderMetadata responderMetadata, Credential metadataSigningCredential) throws SecurityException {
        IDPSSODescriptor idpDescriptor = OpenSAMLUtils.buildObject(IDPSSODescriptor.class);
        idpDescriptor.setWantAuthnRequestsSigned(TRUE);
        idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        idpDescriptor.getKeyDescriptors().add(createKeyDescriptor(metadataSigningCredential));
        idpDescriptor.getSingleSignOnServices().addAll(createSingleSignOnServicesBindingLocations(responderMetadata));
        idpDescriptor.getAttributes().addAll(createSupportedAttributes(responderMetadata));
        String nameIDFormat = responderMetadata.getNameIDFormat();
        if (nameIDFormat != null) {
            idpDescriptor.getNameIDFormats().add(createNameIDFormat(nameIDFormat));
        }
        return idpDescriptor;
    }

    private static List<Attribute> createSupportedAttributes(ResponderMetadata responderMetadata) {
        return responderMetadata.getSupportedAttributes().stream().map(attribute -> {
            Attribute entityAttribute = OpenSAMLUtils.buildObject(Attribute.class);
            entityAttribute.setName(attribute.getName());
            entityAttribute.setFriendlyName(attribute.getFriendlyName());
            entityAttribute.setNameFormat(URI_REFERENCE);
            return entityAttribute;
        }).collect(toList());
    }

    private static List<SingleSignOnService> createSingleSignOnServicesBindingLocations(ResponderMetadata responderMetadata) {
        ArrayList<SingleSignOnService> singleSignOnServices = new ArrayList<>();
        String ssoServiceUrl = responderMetadata.getSsoServiceUrl();
        responderMetadata.getSupportedBindings().forEach(supportedBindingUri -> {
            SingleSignOnService ssos = OpenSAMLUtils.buildObject(SingleSignOnService.class);
            ssos.setBinding(supportedBindingUri);
            ssos.setLocation(ssoServiceUrl);
            singleSignOnServices.add(ssos);
        });
        return singleSignOnServices;
    }

    private static NameIDFormat createNameIDFormat(String format) {
        NameIDFormat nameIDFormat = OpenSAMLUtils.buildObject(NameIDFormat.class);
        nameIDFormat.setFormat(format);
        return nameIDFormat;
    }

    private static KeyDescriptor createKeyDescriptor(Credential signingCredential) throws SecurityException {
        KeyDescriptor descriptor = OpenSAMLUtils.buildObject(KeyDescriptor.class);
        descriptor.setUse(SIGNING);
        descriptor.setKeyInfo(createKeyInfo(signingCredential));
        return descriptor;
    }

    public static KeyInfo createKeyInfo(Credential signingCredential) throws SecurityException {
        NamedKeyInfoGeneratorManager generatorManager = DefaultSecurityConfigurationBootstrap.buildBasicKeyInfoGeneratorManager();
        KeyInfoGenerator keyInfoGenerator = generatorManager.getDefaultManager().getFactory(signingCredential).newInstance();
        return keyInfoGenerator.generate(signingCredential);
    }
}
