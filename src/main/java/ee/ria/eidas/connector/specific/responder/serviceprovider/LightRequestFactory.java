package ee.ria.eidas.connector.specific.responder.serviceprovider;

import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.impl.LightRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.signature.XMLSignature;
import org.jetbrains.annotations.NotNull;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

@Slf4j
@Component
public class LightRequestFactory {

    @Autowired
    private AttributeRegistry supportedAttributesRegistry;

    public LightRequest createLightRequest(AuthnRequest authnRequest, String country, String relayState, String spType) {
        String correlationId = getCorrelationId(authnRequest);
        LightRequest.Builder builder = LightRequest.builder()
                .id(correlationId)
                .citizenCountryCode(country)
                .issuer(authnRequest.getIssuer().getValue())
                .nameIdFormat(authnRequest.getNameIDPolicy().getFormat())
                .providerName(authnRequest.getProviderName())
                .requestedAttributes(createRequestedAttributes(authnRequest))
                .spType(spType);

        Optional<AuthnContextClassRef> classRef = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().stream().findFirst();
        classRef.ifPresent(authnContextClassRef -> builder.levelOfAssurance(authnContextClassRef.getAuthnContextClassRef()));

        if (isNotEmpty(relayState)) {
            builder.relayState(relayState);
        } else {
            builder.relayState(UUID.randomUUID().toString());
        }

        return builder.build();
    }

    @NotNull
    String getCorrelationId(AuthnRequest authnRequest) {
        Signature signature = authnRequest.getSignature();
        XMLSignature xmlSignature = ((SignatureImpl) Objects.requireNonNull(signature)).getXMLSignature();
        String signatureDigest = xmlSignature.getSignedInfo().getElement().getTextContent();
        return Hex.encodeHexString(Base64Support.decode(signatureDigest));
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
                AttributeDefinition<?> attribute = supportedAttributesRegistry.getByName(element.getAttribute("Name"));
                if (attribute != null) {
                    requestedAttributesBuilder.put(attribute);
                }
            }
        });
        return requestedAttributesBuilder.build();
    }
}
