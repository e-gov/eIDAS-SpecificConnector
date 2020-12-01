package ee.ria.eidas.connector.specific.controller;

import com.fasterxml.jackson.databind.JsonNode;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SigningMethod;
import ee.ria.eidas.connector.specific.exception.AuthenticationException;
import ee.ria.eidas.connector.specific.exception.BadRequestException;
import ee.ria.eidas.connector.specific.exception.CertificateResolverException;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import ee.ria.eidas.connector.specific.responder.serviceprovider.LightRequestFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.protocol.eidas.LevelOfAssurance;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Element;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;

import static ee.ria.eidas.connector.specific.exception.ResponseStatus.SP_SIGNING_CERT_MISSING_OR_INVALID;
import static eu.eidas.auth.commons.EidasParameterKeys.TOKEN;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static net.logstash.logback.marker.Markers.append;
import static net.logstash.logback.marker.Markers.appendRaw;

@Slf4j
@Controller
@Validated
@RequiredArgsConstructor
public class ServiceProviderController {
    private static final List<String> VALID_NAME_ID_FORMATS = Arrays.asList(NameIDType.UNSPECIFIED, NameIDType.PERSISTENT, NameIDType.TRANSIENT);
    private static final QName REQUESTED_ATTRIBUTES_QNAME = new QName("http://eidas.europa.eu/saml-extensions", "RequestedAttributes", "eidas");
    private final SpecificConnectorProperties specificConnectorProperties;
    private final EidasNodeCommunication eidasNodeCommunication;
    private final SpecificConnectorCommunication specificConnectorCommunication;
    private final LightRequestFactory lightRequestFactory;
    private final ServiceProviderMetadataRegistry metadataRegistry;
    private final AttributeRegistry supportedAttributesRegistry;
    private final ResponseFactory responseFactory;
    private final MappingJackson2XmlHttpMessageConverter messageConverter;

    @GetMapping(value = "/ServiceProvider")
    public ModelAndView get(@RequestParam("SAMLRequest") @Size(min = 1, max = 131072) @Pattern(regexp = "^[A-Za-z0-9+/=]+$") String SAMLRequest,
                            @RequestParam("country") @Pattern(regexp = "^[A-Z]{2}$") String country,
                            @RequestParam(value = "RelayState", required = false) @Pattern(regexp = "^\\p{Print}{0,80}$") String RelayState) throws MalformedURLException {
        String token = processRequest(SAMLRequest, country, RelayState);
        URL redirectUrl = UriComponentsBuilder.fromUri(URI.create(specificConnectorProperties.getSpecificConnectorRequestUrl()))
                .queryParam(TOKEN.getValue(), token)
                .build().toUri().toURL();
        return new ModelAndView("redirect:" + redirectUrl);
    }

    @PostMapping(value = "/ServiceProvider")
    public ModelAndView post(@RequestParam("SAMLRequest") @Size(min = 1, max = 131072) @Pattern(regexp = "^[A-Za-z0-9+/=]+$") String SAMLRequest,
                             @RequestParam("country") @Pattern(regexp = "^[A-Z]{2}$") String country,
                             @RequestParam(value = "RelayState", required = false) @Pattern(regexp = "^\\p{Print}{0,80}$") String RelayState) {
        String token = processRequest(SAMLRequest, country, RelayState);
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.addObject("action", specificConnectorProperties.getSpecificConnectorRequestUrl());
        modelAndView.addObject(TOKEN.getValue(), token);
        modelAndView.setViewName("postBinding");
        return modelAndView;
    }

    @SneakyThrows
    private String processRequest(String samlRequest, String country, String relayState) {
        byte[] decodedAuthnRequest = Base64.getDecoder().decode(samlRequest);
        logAuthnRequest(decodedAuthnRequest, country, relayState);
        AuthnRequest authnRequest = unmarshallAuthnRequest(decodedAuthnRequest);
        if (authnRequest.getIssuer() == null) {
            throw new BadRequestException("SAML request is invalid - missing issuer");
        }
        ServiceProviderMetadata spMetadata = metadataRegistry.get(authnRequest.getIssuer().getValue());
        if (spMetadata == null) {
            throw new BadRequestException("SAML request is invalid - issuer not allowed");
        }
        if (!specificConnectorProperties.getResponderMetadata().getSupportedMemberStates().contains(country)) {
            throw new BadRequestException("SAML request is invalid - country not supported");
        }
        validateAuthnRequest(authnRequest, spMetadata);
        return createLightRequestToken(authnRequest, country, relayState, spMetadata.getType());
    }

    private void validateAuthnRequest(AuthnRequest authnRequest, ServiceProviderMetadata spMetadata) {
        if (authnRequest.getVersion() != SAMLVersion.VERSION_20) {
            throw new BadRequestException("SAML request is invalid - expecting SAML Version to be 2.0");
        }
        if (authnRequest.getRequestedAuthnContext() == null) {
            throw new BadRequestException("SAML request is invalid - missing RequestedAuthnContext");
        }
        long nrOfInvalidLoA = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().stream()
                .map(ref -> LevelOfAssurance.fromString(ref.getAuthnContextClassRef()))
                .filter(Objects::isNull)
                .count();
        if (nrOfInvalidLoA != 0) {
            throw new BadRequestException("SAML request is invalid - invalid Level of Assurance");
        }
        if (authnRequest.getNameIDPolicy() != null && !VALID_NAME_ID_FORMATS.contains(authnRequest.getNameIDPolicy().getFormat())) {
            throw new BadRequestException("SAML request is invalid - invalid NameIDPolicy");
        }
        if (!TRUE.equals(authnRequest.isForceAuthn())) {
            throw new BadRequestException("SAML request is invalid - expecting ForceAuthn to be true");
        }
        if (!FALSE.equals(authnRequest.isPassive())) {
            throw new BadRequestException("SAML request is invalid - expecting IsPassive to be false");
        }
        validateSignature(authnRequest, spMetadata);
        if (!spMetadata.getAssertionConsumerServiceUrl().equals(authnRequest.getAssertionConsumerServiceURL())) {
            throw new BadRequestException("SAML request is invalid - invalid assertion consumer url");
        }
        validateRequestedAttributes(authnRequest);
    }

    private void validateSignature(AuthnRequest authnRequest, ServiceProviderMetadata spMetadata) {
        Signature signature = authnRequest.getSignature();
        if (signature == null) {
            throw new BadRequestException("SAML request is invalid - invalid signature");
        }
        try {
            spMetadata.validate(signature);
        } catch (SignatureException e) {
            throw new BadRequestException("SAML request is invalid - invalid signature", e);
        } catch (CertificateResolverException e) {
            throw new AuthenticationException(authnRequest, SP_SIGNING_CERT_MISSING_OR_INVALID, e);
        }
        String signatureAlgorithm = signature.getSignatureAlgorithm();
        Optional<SigningMethod> supportedSignatureAlgorithm = specificConnectorProperties.getResponderMetadata()
                .getSigningMethods()
                .stream()
                .filter(sm -> sm.getName().equals(signatureAlgorithm))
                .findFirst();
        if (!supportedSignatureAlgorithm.isPresent()) {
            throw new BadRequestException("SAML request is invalid - invalid signature method");
        }
    }

    private void validateRequestedAttributes(AuthnRequest authnRequest) {
        Extensions extensions = authnRequest.getExtensions();
        if (extensions == null) {
            throw new BadRequestException("SAML request is invalid - no requested attributes");
        } else {
            List<XMLObject> bindings = extensions.getUnknownXMLObjects(REQUESTED_ATTRIBUTES_QNAME);
            if (bindings.isEmpty()) {
                throw new BadRequestException("SAML request is invalid - no requested attributes");
            }
            List<XMLObject> requestedAttributes = bindings.get(0).getOrderedChildren();
            if (requestedAttributes == null || requestedAttributes.isEmpty()) {
                throw new BadRequestException("SAML request is invalid - no requested attributes");
            }
            Optional<Element> unsupportedRequestedAttribute = requestedAttributes.stream()
                    .map(XMLObject::getDOM)
                    .filter(Objects::nonNull)
                    .filter(requestedAttribute -> supportedAttributesRegistry.getByName(requestedAttribute.getAttribute("Name")) == null)
                    .findFirst();
            if (unsupportedRequestedAttribute.isPresent()) {
                throw new BadRequestException("SAML request is invalid - unsupported requested attributes");
            }
        }
    }

    private String createLightRequestToken(AuthnRequest authnRequest, String country, String relayState, String spType) {
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(authnRequest, country, relayState, spType);
        specificConnectorCommunication.putAuthenticationRequest(lightRequest.getId(), authnRequest);
        BinaryLightToken binaryLightToken = eidasNodeCommunication.putLightRequest(lightRequest);
        return BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken);
    }

    @SneakyThrows
    public AuthnRequest unmarshallAuthnRequest(byte[] decodedAuthnRequest) {
        try {
            return OpenSAMLUtils.unmarshall(decodedAuthnRequest, AuthnRequest.class);
        } catch (UnmarshallingException e) {
            throw new BadRequestException("SAML request is invalid", e);
        } catch (XMLParserException e) {
            throw new BadRequestException("SAML request is invalid - does not conform to schema", e);
        }
    }

    protected void logAuthnRequest(byte[] decodedAuthnRequest, String country, String relayState) {
        try {
            JsonNode samlRequestJson = messageConverter.getObjectMapper().readTree(decodedAuthnRequest);
            log.info(appendRaw("authn_request", samlRequestJson.toString())
                            .and(append("authn_request.country", country))
                            .and(append("authn_request.relay_state", relayState))
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "start")),
                    "SAML AuthNRequest received");
        } catch (IOException e) {
            log.error("Unable to convert AuthnRequest from xml to json", e);
        }
    }
}
