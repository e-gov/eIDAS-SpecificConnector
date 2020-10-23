package ee.ria.eidas.connector.specific.integration;

import com.google.common.collect.ImmutableSet;
import ee.ria.eidas.connector.specific.exception.BadRequestException;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import eu.eidas.auth.commons.attribute.*;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap.ImmutableAttributeEntry;
import eu.eidas.auth.commons.exceptions.SecurityEIDASException;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import eu.eidas.specificcommunication.protocol.util.SecurityUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.xml.sax.SAXException;

import javax.annotation.PostConstruct;
import javax.cache.Cache;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.sax.SAXSource;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collection;
import java.util.Optional;

import static eu.eidas.specificcommunication.BinaryLightTokenHelper.createBinaryLightToken;
import static eu.eidas.specificcommunication.BinaryLightTokenHelper.getBinaryLightTokenId;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.xml.bind.Marshaller.JAXB_ENCODING;
import static javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Service
public class EidasNodeCommunication {

    @Value("${lightToken.connector.request.issuer.name}")
    private String lightTokenRequestIssuerName;

    @Value("${lightToken.connector.request.secret}")
    private String lightTokenRequestSecret;

    @Value("${lightToken.connector.request.algorithm}")
    private String lightTokenRequestAlgorithm;

    @Getter
    @Value("${lightToken.connector.response.issuer.name}")
    private String lightTokenResponseIssuerName;

    @Value("${lightToken.connector.response.secret}")
    private String lightTokenResponseSecret;

    @Value("${lightToken.connector.response.algorithm}")
    private String lightTokenResponseAlgorithm;

    @Lazy
    @Autowired
    @Qualifier("specificNodeConnectorRequestCache")
    private Cache<String, String> specificNodeConnectorRequestCache;

    @Lazy
    @Autowired
    @Qualifier("nodeSpecificConnectorResponseCache")
    private Cache<String, String> nodeSpecificConnectorResponseCache;

    @Autowired
    private AttributeRegistry supportedAttributesRegistry;

    private static LightJAXBCodec codec;

    static {
        try {
            codec = new LightJAXBCodec(JAXBContext.newInstance(LightRequest.class, LightResponse.class,
                    ImmutableAttributeMap.class, AttributeDefinition.class));
        } catch (JAXBException e) {
            log.error("Unable to instantiate in static initializer ", e);
        }
    }

    @PostConstruct
    public void init() {
        Assert.notNull(lightTokenRequestIssuerName, "lightToken.connector.request.issuer.name cannot be null. Please check your configuration");
        Assert.notNull(lightTokenRequestSecret, "lightToken.connector.request.secret cannot be null. Please check your configuration");
        Assert.notNull(lightTokenRequestAlgorithm, "lightToken.connector.request.algorithm cannot be null. Please check your configuration");
        Assert.notNull(lightTokenResponseIssuerName, "lightToken.connector.response.issuer.name cannot be null. Please check your configuration");
        Assert.notNull(lightTokenResponseSecret, "lightToken.connector.response.secret cannot be null. Please check your configuration");
        Assert.notNull(lightTokenResponseAlgorithm, "lightToken.connector.response.algorithm cannot be null. Please check your configuration");
    }

    public BinaryLightToken putLightRequest(ILightRequest lightRequest) {
        try {
            BinaryLightToken binaryLightToken = createBinaryLightToken(lightTokenRequestIssuerName, lightTokenRequestSecret, lightTokenRequestAlgorithm);
            String tokenId = binaryLightToken.getToken().getId();
            boolean isInserted = specificNodeConnectorRequestCache.putIfAbsent(tokenId, codec.marshall(lightRequest));
            logCacheEvent(lightRequest, tokenId, isInserted);
            return binaryLightToken;
        } catch (SpecificCommunicationException ex) {
            throw new TechnicalException("Unable to put LightRequest to cache", ex);
        }
    }

    public ILightResponse getAndRemoveLightResponse(String binaryLightTokenBase64) {
        Assert.isTrue(StringUtils.isNotEmpty(binaryLightTokenBase64), "Token value cannot be null or empty!");
        try {
            String lightTokenId = getBinaryLightTokenId(binaryLightTokenBase64, lightTokenResponseSecret, lightTokenResponseAlgorithm);
            ILightResponse lightResponse = codec.unmarshallResponse(nodeSpecificConnectorResponseCache.getAndRemove(lightTokenId), supportedAttributesRegistry.getAttributes());
            logCacheEvent(lightTokenId, lightResponse);
            return lightResponse;
        } catch (SpecificCommunicationException | SecurityEIDASException e) {
            throw new BadRequestException("Invalid token", e);
        }
    }

    private void logCacheEvent(ILightRequest lightRequest, String tokenId, boolean isInserted) {
        if (isInserted) {
            log.info(append("light_request", lightRequest).and(append("communication_cache.name", specificNodeConnectorRequestCache.getName()))
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "LightRequest with tokenId: '{}' was saved", value("light_request.light_token_id", tokenId));
        } else {
            log.warn(append("light_request", lightRequest).and(append("communication_cache.name", specificNodeConnectorRequestCache.getName()))
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "LightRequest was not saved. A LightRequest with tokenId: '{}' already exists", value("light_request.light_token_id", tokenId));
        }
    }

    private void logCacheEvent(String lightTokenId, ILightResponse lightResponse) {
        if (lightResponse != null) {
            log.info(append("light_response.id", lightResponse.getId())
                            .and(append("light_response.in_response_to_id", lightResponse.getInResponseToId()))
                            .and(append("communication_cache.name", nodeSpecificConnectorResponseCache.getName()))
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "LightResponse retrieved from cache for tokenId: {}", value("light_response.light_token_id", lightTokenId));
        } else {
            log.warn(append("communication_cache.name", nodeSpecificConnectorResponseCache.getName())
                            .and(append("event.kind", "event"))
                            .and(append("event.category", "authentication"))
                            .and(append("event.type", "info")),
                    "LightResponse was not found from cache for tokenId: {}", value("light_response.light_token_id", lightTokenId));
        }
    }

    @Slf4j
    private static class LightJAXBCodec {
        private final JAXBContext jaxbCtx;

        public LightJAXBCodec(JAXBContext jaxbCtx) {
            this.jaxbCtx = jaxbCtx;
        }

        public <T> String marshall(T input) throws SpecificCommunicationException {
            if (input == null) {
                return null;
            }
            StringWriter writer = new StringWriter();
            try {
                createMarshaller().marshal(input, writer);
            } catch (JAXBException e) {
                throw new SpecificCommunicationException(e);
            }
            return writer.toString();
        }

        @SuppressWarnings("unchecked")
        public <T extends ILightResponse> T unmarshallResponse(String input, Collection<AttributeDefinition<?>> registry)
                throws SpecificCommunicationException {
            if (input == null) {
                return null;
            }
            if (registry == null) {
                throw new SpecificCommunicationException("missing registry");
            }
            try {
                SAXSource secureSaxSource = SecurityUtils.createSecureSaxSource(input);
                T unmarshalled = (T) createUnmarshaller().unmarshal(secureSaxSource);
                LightResponse.Builder resultBuilder = LightResponse.builder(unmarshalled);
                ImmutableAttributeMap.Builder mapBuilder = ImmutableAttributeMap.builder();
                for (ImmutableAttributeEntry<?> entry : unmarshalled.getAttributes().entrySet()) {
                    URI nameUri = entry.getKey().getNameUri();
                    AttributeDefinition<?> definition = getByName(nameUri, registry);
                    ImmutableSet values = unmarshalValues(entry, definition);
                    mapBuilder.put(definition, values);
                }
                return (T) resultBuilder.attributes(mapBuilder.build()).build();
            } catch (JAXBException | AttributeValueMarshallingException | SAXException | ParserConfigurationException e) {
                throw new SpecificCommunicationException(e);
            }
        }

        private ImmutableSet<AttributeValue<?>> unmarshalValues(ImmutableAttributeEntry<?> entry, AttributeDefinition<?> definition)
                throws AttributeValueMarshallingException {
            ImmutableSet.Builder<AttributeValue<?>> valuesBuilder = ImmutableSet.builder();
            AttributeValueMarshaller<?> valueMarshaller = definition.getAttributeValueMarshaller();
            for (Object value : entry.getValues()) {
                valuesBuilder.add(valueMarshaller.unmarshal(value.toString(), definition.isTransliterationMandatory()));
            }
            return valuesBuilder.build();
        }

        private AttributeDefinition<?> getByName(URI nameUri, Collection<AttributeDefinition<?>> registry) throws SpecificCommunicationException {
            Assert.notNull(nameUri, "nameUri cannot be null");
            Optional<AttributeDefinition<?>> firstMatch = registry.stream()
                    .filter(attributeDefinition -> nameUri.equals(attributeDefinition.getNameUri()))
                    .findFirst();
            if (firstMatch.isPresent()) {
                return firstMatch.get();
            } else {
                throw new SpecificCommunicationException(format("Attribute %s not present in the registry", nameUri));
            }
        }

        private Marshaller createMarshaller() throws JAXBException {
            Marshaller marshaller = jaxbCtx.createMarshaller();
            marshaller.setProperty(JAXB_ENCODING, UTF_8.name());
            marshaller.setProperty(JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            return marshaller;
        }

        private Unmarshaller createUnmarshaller() throws JAXBException {
            return jaxbCtx.createUnmarshaller();
        }
    }
}
