package ee.ria.eidas.connector.specific.config;

import lombok.Getter;
import lombok.NoArgsConstructor;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

@Configuration
public class OpenSAMLConfiguration {

    @PostConstruct
    private void init() throws ComponentInitializationException, InitializationException {
        BasicParserPool parserPool = setupBasicParserPool();
        Security.addProvider(new BouncyCastleProvider());
        InitializationService.initialize();
        AlgorithmSupport.getGlobalAlgorithmRegistry().register(new SignatureRSASHA256MGF1());
        setupXmlObjectProviderRegistry(parserPool);
    }

    private BasicParserPool setupBasicParserPool() throws ComponentInitializationException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);
        parserPool.setIgnoreElementContentWhitespace(true);
        Map<String, Object> builderAttributes = new HashMap<>();
        parserPool.setBuilderAttributes(builderAttributes);

        Map<String, Boolean> features = new HashMap<>();
        features.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
        features.put("http://xml.org/sax/features/external-general-entities", FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", FALSE);

        parserPool.setBuilderFeatures(features);
        parserPool.initialize();
        return parserPool;
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
