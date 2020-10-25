package ee.ria.eidas.connector.specific.util;

import lombok.experimental.UtilityClass;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.jetbrains.annotations.NotNull;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.springframework.util.ResourceUtils.getFile;

@UtilityClass
public class TestUtils {
    public static final String UUID_REGEX = "[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}";
    public static final String SECURE_RANDOM_REGEX = "^[_].{32,64}$";

    public Status getStatus(String samlResponseBase64) throws XMLParserException, UnmarshallingException {
        return getResponse(samlResponseBase64).getStatus();
    }

    public Response getResponse(String samlResponseBase64) throws XMLParserException, UnmarshallingException {
        byte[] decodedSamlResponse = Base64.getDecoder().decode(samlResponseBase64);
        return (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(decodedSamlResponse));
    }

    @NotNull
    public String getAuthnRequestAsBase64(String resourceLocation) throws IOException {
        byte[] authnRequest = readFileToByteArray(getFile(resourceLocation));
        return Base64Support.encode(authnRequest, false);
    }

    public Element getXmlDocument(String xml) throws SAXException, IOException, ParserConfigurationException {
        return DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();
    }

    public Credential getServiceProviderEncryptionCredential() throws ResolverException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put("service-provider-response-encryption", "changeit");
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(serviceProviderKeyStore(), passwordMap);
        CriteriaSet criteria = new CriteriaSet(new EntityIdCriterion("service-provider-response-encryption"));
        return resolver.resolveSingle(criteria);
    }

    private KeyStore serviceProviderKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        byte[] spKeystore = readFileToByteArray(getFile("classpath:__files/mock_keys/service-provider-metadata-keystore.p12"));
        keystore.load(new ByteArrayInputStream(spKeystore), "changeit".toCharArray());
        return keystore;
    }
}
