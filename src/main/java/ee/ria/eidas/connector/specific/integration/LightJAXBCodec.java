package ee.ria.eidas.connector.specific.integration;

import ee.ria.eidas.connector.specific.exception.TechnicalException;
import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.ILightResponse;
import eu.eidas.specificcommunication.LightRequest;
import eu.eidas.specificcommunication.LightResponse;
import eu.eidas.specificcommunication.protocol.util.LightMessagesConverter;
import eu.eidas.specificcommunication.protocol.util.SecurityUtils;
import lombok.extern.slf4j.Slf4j;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.sax.SAXSource;
import java.io.StringWriter;
import java.util.Collection;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
public class LightJAXBCodec {
    protected static final Class<?>[] LIGHT_REQUEST_CODEC = {LightRequest.class};
    protected static final Class<?>[] LIGHT_RESPONSE_CODEC = {LightResponse.class};
    private final LightMessagesConverter messagesConverter = new LightMessagesConverter();
    private final JAXBContext lightRequestJAXBCtx;
    private final JAXBContext lightResponseJAXBCtx;

    LightJAXBCodec(JAXBContext lightRequestJAXBCtx, JAXBContext lightResponseJAXBCtx) {
        this.lightRequestJAXBCtx = lightRequestJAXBCtx;
        this.lightResponseJAXBCtx = lightResponseJAXBCtx;
    }

    public static LightJAXBCodec buildDefault() {
        JAXBContext lightRequestJAXBContext = getJAXBContext(LIGHT_REQUEST_CODEC);
        JAXBContext lightResponseJAXBContext = getJAXBContext(LIGHT_RESPONSE_CODEC);
        return new LightJAXBCodec(lightRequestJAXBContext, lightResponseJAXBContext);
    }

    private static JAXBContext getJAXBContext(Class<?>[] contextClasses) {
        try {
            return JAXBContext.newInstance(contextClasses);
        } catch (JAXBException e) {
            throw new IllegalArgumentException("Unable to instantiate the JAXBContext", e);
        }
    }

    public String marshall(ILightRequest lightRequest) {
        try {
            LightRequest xmlLightRequest = messagesConverter.convert(lightRequest);
            return marshall(xmlLightRequest);
        } catch (Exception e) {
            throw new TechnicalException("Invalid LightResponse", e);
        }
    }

    public String marshall(ILightResponse lightResponse) {
        try {
            LightResponse xmlLightResponse = messagesConverter.convert(lightResponse);
            return marshall(xmlLightResponse);
        } catch (Exception e) {
            throw new TechnicalException("Invalid LightResponse", e);
        }
    }

    private <T> String marshall(T input) throws JAXBException {
        if (input == null) {
            return null;
        }
        StringWriter writer = new StringWriter();
        createMarshaller(input.getClass()).marshal(input, writer);
        return writer.toString();
    }

    public ILightResponse unmarshallResponse(String input, Collection<AttributeDefinition<?>> registry) {
        if (input == null) {
            return null;
        }
        if (registry == null) {
            throw new TechnicalException("Failed to unmarshal LightResponse! Missing attribute registry.");
        }
        try {
            SAXSource secureSaxSource = SecurityUtils.createSecureSaxSource(input);
            LightResponse rawResponse = (LightResponse) createUnmarshaller().unmarshal(secureSaxSource);
            return messagesConverter.convert(rawResponse, registry);
        } catch (Exception e) {
            throw new TechnicalException("Invalid LightResponse", e);
        }
    }

    private Marshaller createMarshaller(Class<?> srcType) throws JAXBException {
        Marshaller marshaller;
        if (LightRequest.class.isAssignableFrom(srcType)) {
            marshaller = lightRequestJAXBCtx.createMarshaller();
        } else {
            marshaller = lightResponseJAXBCtx.createMarshaller();
        }
        marshaller.setProperty(Marshaller.JAXB_ENCODING, UTF_8.name()); // NOI18N
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        return marshaller;
    }

    private Unmarshaller createUnmarshaller() throws JAXBException {
        return lightResponseJAXBCtx.createUnmarshaller();
    }
}
