package ee.ria.eidas.connector.specific.responder.serviceprovider;

import ee.ria.eidas.connector.specific.exception.SpecificConnectorException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.X509Certificate;

import java.security.cert.CertificateException;
import java.time.Clock;
import java.util.Date;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

@Slf4j
@RequiredArgsConstructor
public class ServiceProviderValidationFilter implements MetadataFilter {
    public static final String INVALID_ENTITY_ID = "Invalid Service provider metadata entityId: %s";
    private final String entityId;
    private final Clock clock;

    @Nullable
    @Override
    public XMLObject filter(@Nullable XMLObject metadata) throws FilterException {
        if (metadata == null) {
            return null;
        }
        EntityDescriptor entityDescriptor = (EntityDescriptor) metadata;
        validateEntityId(entityDescriptor);
        validateSPSSODescriptor(entityDescriptor);
        return metadata;
    }

    private void validateEntityId(EntityDescriptor entityDescriptor) {
        if (!entityId.equals(entityDescriptor.getEntityID())) {
            throw new SpecificConnectorException(INVALID_ENTITY_ID, entityDescriptor.getEntityID());
        }
    }

    private void validateSPSSODescriptor(EntityDescriptor entityDescriptor) throws FilterException {
        SPSSODescriptor spDescriptor = getSPSSODescriptor(entityDescriptor);
        validateNameIDFormat(spDescriptor);
        validateAssertionConsumerServiceBinding(spDescriptor);
        validateSPSSOCertificates(spDescriptor);
    }

    private void validateSPSSOCertificates(SPSSODescriptor spDescriptor) throws FilterException {
        List<X509Certificate> certificates = spDescriptor.getKeyDescriptors().stream()
                .map(KeyDescriptor::getKeyInfo)
                .flatMap(keyInfo -> keyInfo.getX509Datas().stream())
                .flatMap(x509Data -> x509Data.getX509Certificates().stream())
                .collect(toList());

        for (X509Certificate certificate : certificates) {
            validateCertificate(certificate);
        }
    }

    private void validateAssertionConsumerServiceBinding(SPSSODescriptor spDescriptor) throws FilterException {
        boolean isInvalidBinding = spDescriptor.getAssertionConsumerServices().stream()
                .anyMatch(acs -> !SAML2_POST_BINDING_URI.equals(acs.getBinding()) && !SAML2_REDIRECT_BINDING_URI.equals(acs.getBinding()));

        if (isInvalidBinding) {
            throw new FilterException("Invalid Service Provider metadata assertion consumer service binding");
        }
    }

    private void validateNameIDFormat(SPSSODescriptor spDescriptor) throws FilterException {
        boolean isInvalidNameIDFormat = spDescriptor.getNameIDFormats().stream()
                .anyMatch(nameIDFormat -> !NameIDType.UNSPECIFIED.equals(nameIDFormat.getFormat()));

        if (isInvalidNameIDFormat) {
            throw new FilterException("Invalid Service Provider metadata NameIDFormat");
        }
    }

    private SPSSODescriptor getSPSSODescriptor(EntityDescriptor entityDescriptor) throws FilterException {
        List<RoleDescriptor> roles = entityDescriptor.getRoleDescriptors();
        return roles.stream()
                .filter(SPSSODescriptor.class::isInstance)
                .map(SPSSODescriptor.class::cast)
                .findFirst()
                .orElseThrow(() -> new FilterException("Missing Service Provider metadata role descriptor"));
    }

    private void validateCertificate(X509Certificate cert) throws FilterException {
        Date currentDate = new Date(clock.millis());
        try {
            requireNonNull(cert.getValue());
            requireNonNull(X509Support.decodeCertificate(cert.getValue())).checkValidity(currentDate);
        } catch (CertificateException e) {
            throw new FilterException("Invalid SPSSODescriptor certificate", e);
        }
    }
}
