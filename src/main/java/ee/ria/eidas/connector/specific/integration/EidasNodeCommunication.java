package ee.ria.eidas.connector.specific.integration;

import com.google.common.collect.ImmutableSet;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import eu.eidas.auth.commons.attribute.*;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap.ImmutableAttributeEntry;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import eu.eidas.specificcommunication.exception.SpecificCommunicationException;
import eu.eidas.specificcommunication.protocol.util.SecurityUtils;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import javax.annotation.PostConstruct;
import javax.cache.Cache;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.sax.SAXSource;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collection;
import java.util.Optional;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.xml.bind.Marshaller.JAXB_ENCODING;
import static javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT;
import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

@Slf4j
@Service
public class EidasNodeCommunication {

    @Value("${lightToken.connector.request.issuer.name}")
    private String lightTokenRequestIssuerName;

    @Value("${lightToken.connector.request.secret}")
    private String lightTokenRequestSecret;

    @Value("${lightToken.connector.request.algorithm}")
    private String lightTokenRequestAlgorithm;

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

    @NonNull
    public BinaryLightToken putLightRequest(@NonNull ILightRequest lightRequest) {
        BinaryLightToken binaryLightToken = createBinaryLightToken();
        String alwaysUniqueTokenId = binaryLightToken.getToken().getId();
        specificNodeConnectorRequestCache.put(alwaysUniqueTokenId, codec.marshall(lightRequest));
        log.info(append("light_request", lightRequest).
                        and(append("communication_cache.name", specificNodeConnectorRequestCache.getName()))
                        .and(append("event.kind", "event"))
                        .and(append("event.category", "authentication"))
                        .and(append("event.type", "info")),
                "Put LightRequest to cache with tokenId: '{}'", value("light_request.light_token_id", alwaysUniqueTokenId));
        return binaryLightToken;
    }

    @Nullable
    public ILightResponse getAndRemoveLightResponse(@NonNull String binaryLightTokenBase64) {
        Assert.isTrue(isNotEmpty(binaryLightTokenBase64), "Token value cannot be null or empty!");
        String lightTokenId = getBinaryLightTokenId(binaryLightTokenBase64);
        String lightResponseXml = nodeSpecificConnectorResponseCache.getAndRemove(lightTokenId);
        ILightResponse lightResponse = codec.unmarshallResponse(lightResponseXml, supportedAttributesRegistry.getAttributes());
        LogstashMarker markers = append("communication_cache.name", nodeSpecificConnectorResponseCache.getName())
                .and(append("event.kind", "event"))
                .and(append("event.category", "authentication"))
                .and(append("event.type", "info"));
        if (lightResponse != null) {
            markers.and(append("light_response", lightResponse));
            markers.and(append("light_request.id", lightResponse.getInResponseToId()));
        }
        log.info(markers,
                "Get and remove LightResponse from cache for tokenId: {},  Result found: {}",
                value("light_response.light_token_id", lightTokenId), value("communication_cache.result", lightResponseXml != null));
        return lightResponse;
    }

    private BinaryLightToken createBinaryLightToken() {
        try {
            return BinaryLightTokenHelper.createBinaryLightToken(lightTokenRequestIssuerName, lightTokenRequestSecret, lightTokenRequestAlgorithm);
        } catch (SpecificCommunicationException ex) {
            throw new TechnicalException("Unable to create BinaryLightToken", ex);
        }
    }

    private String getBinaryLightTokenId(String binaryLightTokenBase64) {
        try {
            return BinaryLightTokenHelper.getBinaryLightTokenId(binaryLightTokenBase64, lightTokenResponseSecret, lightTokenResponseAlgorithm);
        } catch (SpecificCommunicationException ex) {
            throw new TechnicalException("Unable to create BinaryLightTokenId", ex);
        }
    }

    @Slf4j
    public static class LightJAXBCodec {
        private final JAXBContext jaxbCtx;

        public LightJAXBCodec(JAXBContext jaxbCtx) {
            this.jaxbCtx = jaxbCtx;
        }

        public <T> String marshall(T input) {
            if (input == null) {
                return null;
            }
            StringWriter writer = new StringWriter();
            try {
                createMarshaller().marshal(input, writer);
            } catch (JAXBException e) {
                throw new TechnicalException("Invalid LightResponse", e);
            }
            return writer.toString();
        }

        @Nullable
        @SuppressWarnings("unchecked")
        public <T extends ILightResponse> T unmarshallResponse(String input, Collection<AttributeDefinition<?>> registry) {
            if (input == null) {
                return null;
            }
            if (registry == null) {
                throw new TechnicalException("Invalid LightResponse. Missing attribute registry");
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
            } catch (Exception e) {
                throw new TechnicalException("Invalid LightResponse", e);
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

        private AttributeDefinition<?> getByName(URI nameUri, Collection<AttributeDefinition<?>> registry) {
            Assert.notNull(nameUri, "nameUri cannot be null");
            Optional<AttributeDefinition<?>> firstMatch = registry.stream()
                    .filter(attributeDefinition -> nameUri.equals(attributeDefinition.getNameUri()))
                    .findFirst();
            if (firstMatch.isPresent()) {
                return firstMatch.get();
            } else {
                throw new TechnicalException(format("Invalid LightResponse. Attribute %s not present in the registry", nameUri));
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
