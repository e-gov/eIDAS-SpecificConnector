package ee.ria.eidas.connector.specific.metadata.validation;

import ee.ria.eidas.connector.specific.exception.SpecificConnectorException;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.X509Certificate;

import javax.xml.namespace.QName;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

@Slf4j
public class ServiceProviderValidationFilter implements MetadataFilter {
    public static final String INVALID_ENTITY_ID = "Invalid Service provider metadata entity id: %s";
    public static final String INVALID_SP_TYPE = "Invalid Service provider metadata SPType";
    private final String entityId;
    private final String spType;
    private final QName spTypeQName;

    public ServiceProviderValidationFilter(String entityId, String spType) {
        this.entityId = entityId;
        this.spType = spType;
        this.spTypeQName = new QName("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
    }

    @Nullable
    @Override
    public XMLObject filter(@Nullable XMLObject metadata) {
        if (metadata instanceof EntityDescriptor) {
            EntityDescriptor entityDescriptor = (EntityDescriptor) metadata;
            validateEntityId(entityDescriptor);
            validateSPType(entityDescriptor);
            validateSPSSODescriptor(entityDescriptor);
        } else {
            throw new SpecificConnectorException("Invalid Service provider metadata format");
        }
        return metadata;
    }

    private void validateEntityId(EntityDescriptor entityDescriptor) {
        if (!entityId.equals(entityDescriptor.getEntityID())) {
            throw new SpecificConnectorException(INVALID_ENTITY_ID, entityDescriptor.getEntityID());
        }
    }

    private void validateSPType(EntityDescriptor entityDescriptor) {
        List<XMLObject> spTypes = entityDescriptor.getExtensions().getUnknownXMLObjects(spTypeQName);

        if (spTypes.isEmpty() || !spType.equals(((XSAny) spTypes.get(0)).getTextContent())) {
            throw new SpecificConnectorException(INVALID_SP_TYPE);
        }
    }

    private void validateSPSSODescriptor(EntityDescriptor entityDescriptor) {
        SPSSODescriptor spDescriptor = getSPSSODescriptor(entityDescriptor);
        validateNameIDFormat(spDescriptor);
        validateAssertionConsumerServiceBinding(spDescriptor);
        validateSPSSOCertificates(spDescriptor);
    }

    private void validateSPSSOCertificates(SPSSODescriptor spDescriptor) {
        List<X509Certificate> certificates = spDescriptor.getKeyDescriptors().stream()
                .map(KeyDescriptor::getKeyInfo)
                .flatMap(keyInfo -> keyInfo.getX509Datas().stream())
                .flatMap(x509Data -> x509Data.getX509Certificates().stream())
                .collect(toList());

        for (X509Certificate certificate : certificates) {
            validateCertificate(certificate);
        }
    }

    private void validateAssertionConsumerServiceBinding(SPSSODescriptor spDescriptor) {
        boolean isInvalidBinding = spDescriptor.getAssertionConsumerServices().stream()
                .anyMatch(acs -> !SAML2_POST_BINDING_URI.equals(acs.getBinding()) && !SAML2_REDIRECT_BINDING_URI.equals(acs.getBinding()));

        if (isInvalidBinding) {
            throw new SpecificConnectorException("Invalid Service Provider metadata assertion consumer service binding");
        }
    }

    private void validateNameIDFormat(SPSSODescriptor spDescriptor) {
        boolean isInvalidNameIDFormat = spDescriptor.getNameIDFormats().stream()
                .anyMatch(nameIDFormat -> !NameIDType.UNSPECIFIED.equals(nameIDFormat.getFormat()));

        if (isInvalidNameIDFormat) {
            throw new SpecificConnectorException("Invalid Service Provider metadata NameIDType");
        }
    }

    private SPSSODescriptor getSPSSODescriptor(EntityDescriptor entityDescriptor) {
        List<RoleDescriptor> roles = entityDescriptor.getRoleDescriptors();
        return roles.stream()
                .filter(SPSSODescriptor.class::isInstance)
                .map(SPSSODescriptor.class::cast)
                .findFirst()
                .orElseThrow(() -> new SpecificConnectorException("Missing Service Provider metadata role descriptor"));
    }

    private void validateCertificate(X509Certificate cert) {
        try {
            requireNonNull(cert.getValue());
            requireNonNull(X509Support.decodeCertificate(cert.getValue())).checkValidity();
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new SpecificConnectorException("Expired Service Provider metadata SPSSODescriptor certificate", e);
        } catch (NullPointerException | CertificateException e) {
            throw new SpecificConnectorException("Invalid Service Provider metadata SPSSODescriptor certificate", e);
        }
    }
}
