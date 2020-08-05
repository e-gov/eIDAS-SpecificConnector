package ee.ria.eidas.connector.specific.saml;

import ee.ria.eidas.connector.specific.exception.BadRequestException;
import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadataResolver;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.impl.LightRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.opensaml.core.xml.util.XMLObjectSupport.unmarshallFromInputStream;

@Slf4j
@Component
public class LightRequestFactory {

    @Autowired
    private ServiceProviderMetadataResolver spMetadataResolver;

    @Autowired
    private AttributeRegistry eidasAttributeRegistry;

    @Autowired
    private ParserPool parserPool;

    public LightRequest createLightRequest(String samlRequest, String country, String relayState) {
        try {
            byte[] decodedAuthnRequest = Base64.getDecoder().decode(samlRequest);
            AuthnRequest authnRequest = (AuthnRequest) unmarshallFromInputStream(parserPool, new ByteArrayInputStream(decodedAuthnRequest));
            ServiceProviderMetadata spMetadata = spMetadataResolver.getByEntityId(authnRequest.getIssuer().getValue());
            spMetadata.validate(authnRequest.getSignature());

            LightRequest.Builder builder = LightRequest.builder()
                    .id(authnRequest.getID())
                    .citizenCountryCode(country)
                    .issuer(authnRequest.getIssuer().getValue())
                    .nameIdFormat(authnRequest.getNameIDPolicy().getFormat())
                    .providerName(authnRequest.getProviderName())
                    .requestedAttributes(createRequestedAttributes(authnRequest))
                    .spType(spMetadata.getServiceProvider().getType());

            Optional<AuthnContextClassRef> classRef = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().stream().findFirst();
            classRef.ifPresent(authnContextClassRef -> builder.levelOfAssurance(authnContextClassRef.getAuthnContextClassRef()));

            if (isNotEmpty(relayState)) {
                builder.relayState(relayState);
            }

            return builder.build();
        } catch (Exception e) {
            throw new BadRequestException("Invalid authentication request", e);
        }
    }

    private ImmutableAttributeMap createRequestedAttributes(AuthnRequest authn) {
        Extensions extensions = authn.getExtensions();
        if (extensions == null) {
            return null;
        }
        QName requestedAttributesQName = new QName("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");
        List<XMLObject> bindings = extensions.getUnknownXMLObjects(requestedAttributesQName);
        if (bindings.isEmpty()) {
            return null;
        }
        XMLObject requestedAttributes = bindings.get(0);
        if (requestedAttributes.getOrderedChildren() == null) {
            return null;
        }
        ImmutableAttributeMap.Builder requestedAttributesBuilder = ImmutableAttributeMap.builder();
        requestedAttributes.getOrderedChildren().forEach(requestedAttribute -> {
            Element element = requestedAttribute.getDOM();
            if (element != null) {
                AttributeDefinition<?> attribute = eidasAttributeRegistry.getByName(element.getAttribute("Name"));
                if (attribute != null) {
                    requestedAttributesBuilder.put(attribute);
                }
            }
        });
        return requestedAttributesBuilder.build();
    }
}
