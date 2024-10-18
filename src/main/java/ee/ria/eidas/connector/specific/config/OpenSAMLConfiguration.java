package ee.ria.eidas.connector.specific.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.dataformat.xml.JacksonXmlModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ClasspathResolver;
import net.shibboleth.utilities.java.support.xml.SchemaBuilder;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;
import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

@Configuration
@RequiredArgsConstructor
public class OpenSAMLConfiguration {
    public static final String DEFAULT_TEXT_ELEMENT_NAME = "Value";
    private final ResourceLoader resourceLoader;

    @PostConstruct
    private void init() throws ComponentInitializationException, InitializationException, SAXException, IOException {
        BasicParserPool parserPool = setupSecureSchemaValidatingParserPool();
        Security.addProvider(new BouncyCastleProvider());
        InitializationService.initialize();
        AlgorithmSupport.getGlobalAlgorithmRegistry().register(new SignatureRSASHA256MGF1());
        setupXmlObjectProviderRegistry(parserPool);
    }

    @Bean
    public MappingJackson2XmlHttpMessageConverter messageConverter() {
        JacksonXmlModule jacksonXmlModule = new JacksonXmlModule();
        jacksonXmlModule.setXMLTextElementName(DEFAULT_TEXT_ELEMENT_NAME);
        XmlMapper objectMapper = new XmlMapper(jacksonXmlModule);
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        ObjectMapper.findModules().forEach(objectMapper::registerModule);
        return new MappingJackson2XmlHttpMessageConverter(objectMapper);
    }

    private BasicParserPool setupSecureSchemaValidatingParserPool() throws ComponentInitializationException, SAXException, IOException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);
        parserPool.setIgnoreElementContentWhitespace(false);

        Schema samlSchema = getSAMLSchema();
        parserPool.setSchema(samlSchema);

        Map<String, Boolean> features = new HashMap<>();
        features.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
        features.put("http://apache.org/xml/features/nonvalidating/load-external-dtd", FALSE);
        features.put("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
        features.put("http://xml.org/sax/features/external-general-entities", FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", FALSE);

        parserPool.setBuilderFeatures(features);
        parserPool.initialize();
        return parserPool;
    }

    private Schema getSAMLSchema() throws IOException, SAXException {
        SchemaBuilder schemaBuilder = new SchemaBuilder();
        schemaBuilder.addSchema(resourceLoader.getResource("classpath:saml/saml_eidas_extension.xsd").getInputStream());
        schemaBuilder.setResourceResolver(new ClasspathResolver());
        SAMLSchemaBuilder samlSchemaBuilder = new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11);
        samlSchemaBuilder.setSchemaBuilder(schemaBuilder);
        return samlSchemaBuilder.getSAMLSchema();
    }

    private void setupXmlObjectProviderRegistry(BasicParserPool parserPool) {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        if (registry == null) {
            registry = new XMLObjectProviderRegistry();
            ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
        }
        registry.setParserPool(parserPool);
    }

    @Getter
    @NoArgsConstructor
    public static final class SignatureRSASHA256MGF1 implements SignatureAlgorithm {
        String key = JCAConstants.KEY_ALGO_RSA;
        String URI = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1;
        AlgorithmType type = AlgorithmType.Signature;
        String JCAAlgorithmID = "SHA256withRSAandMGF1";
        String digest = JCAConstants.DIGEST_SHA256;
    }
}
