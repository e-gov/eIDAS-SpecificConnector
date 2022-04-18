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
import org.opensaml.core.xml.schema.XSAny;
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
    public static final QName SPTYPE_QNAME = new QName("http://eidas.europa.eu/saml-extensions", "SPType", "eidas");
    public static final QName REQUESTER_ID_QNAME = new QName("http://eidas.europa.eu/saml-extensions", "RequesterID", "eidas");
    public static final QName REQUESTED_ATTRIBUTES_QNAME = new QName("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");

    @Autowired
    private AttributeRegistry supportedAttributesRegistry;

    public LightRequest createLightRequest(AuthnRequest authnRequest, String country, String relayState) {
        String correlationId = getCorrelationId(authnRequest);
        String requesterId = getExtensionValue(authnRequest, REQUESTER_ID_QNAME);
        String spType = getExtensionValue(authnRequest, SPTYPE_QNAME);
        LightRequest.Builder builder = LightRequest.builder()
                .id(correlationId)
                .citizenCountryCode(country)
                .issuer(authnRequest.getIssuer().getValue())
                .providerName(authnRequest.getProviderName())
                .requestedAttributes(createRequestedAttributes(authnRequest))
                .spType(spType)
                .requesterId(requesterId);

        if (authnRequest.getNameIDPolicy() != null) {
            builder.nameIdFormat(authnRequest.getNameIDPolicy().getFormat());
        }

        Optional<AuthnContextClassRef> classRef = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().stream().findFirst();
        classRef.ifPresent(authnContextClassRef -> builder.levelOfAssurance(authnContextClassRef.getAuthnContextClassRef()));

        if (isNotEmpty(relayState)) {
            builder.relayState(relayState);
        } else {
            builder.relayState(UUID.randomUUID().toString());
        }

        return builder.build();
    }

    private String getExtensionValue(AuthnRequest authnRequest, QName extensionName) {
        List<XMLObject> extensions = authnRequest.getExtensions().getUnknownXMLObjects();
        XMLObject element = extensions.stream()
                .filter(xmlObject -> xmlObject.getElementQName().equals(extensionName))
                .findFirst()
                .get();
        return ((XSAny)element).getTextContent();
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
        List<XMLObject> bindings = extensions.getUnknownXMLObjects(REQUESTED_ATTRIBUTES_QNAME);
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
