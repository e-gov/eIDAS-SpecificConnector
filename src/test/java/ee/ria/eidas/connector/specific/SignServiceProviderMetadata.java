package ee.ria.eidas.connector.specific;

import lombok.SneakyThrows;
import org.jetbrains.annotations.NotNull;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class SignServiceProviderMetadata {

    private static final String SP_KEYSTORE_FILE =
            "./src/test/resources/__files/mock_keys/service-provider-metadata-keystore.p12";
    private static final String SP_KEYSTORE_PASSWORD = "changeit";
    private static final String SP_KEY_ALIAS = "service-provider-metadata-signing";
    private static final String SP_KEY_PASSWORD = "changeit";

    private static final String SP1_KEYSTORE_FILE =
            "./src/test/resources/__files/mock_keys/service-provider-1-metadata-keystore.p12";
    private static final String SP1_KEYSTORE_PASSWORD = "changeit";
    private static final String SP1_KEY_ALIAS = "service-provider-1-metadata-signing";
    private static final String SP1_KEY_PASSWORD = "changeit";

    private static final String XML_FOLDER = "./src/test/resources/__files/sp_metadata/";
    private static final String XML_ELEMENT_NAME = "EntityDescriptor";
    private static final String XML_ELEMENT_XMLNS = "urn:oasis:names:tc:SAML:2.0:metadata";

    /* Utility script to resign mock service provider metadata responses.
     * See `src/test/resources/__files/sp_metadata/README.md` for more information. */
    public static void main(String[] args) {
        List<String> resignSp = List.of(
                "sp-valid-metadata.xml",
                "sp-expired-response-encryption-cert.xml",
                "sp-invalid-entity-id.xml",
                "sp-invalid-signer-cert.xml",
                "sp-expired-request-signing-cert.xml"
        );
        KeyStore spKeystore = loadKeyStore(SP_KEYSTORE_FILE, SP_KEYSTORE_PASSWORD);
        for (String xmlFile : resignSp) {
            resign(
                    XML_FOLDER + xmlFile,
                    spKeystore,
                    SP_KEY_ALIAS,
                    SP_KEY_PASSWORD);
        }
        List<String> resignSp1 = List.of(
                "sp-invalid-signer-cert.xml",
                "sp1-valid-metadata.xml"
        );
        KeyStore sp1Keystore = loadKeyStore(SP1_KEYSTORE_FILE, SP1_KEYSTORE_PASSWORD);
        for (String xmlFile : resignSp1) {
            resign(
                    XML_FOLDER + xmlFile,
                    sp1Keystore,
                    SP1_KEY_ALIAS,
                    SP1_KEY_PASSWORD);
        }
    }

    @SneakyThrows
    private static void resign(String xmlFile, KeyStore keystore, String keyAlias, String keyPassword) {
        Key key = keystore.getKey(keyAlias, keyPassword.toCharArray());
        if (!(key instanceof PrivateKey privateKey)) {
            throw new RuntimeException(String.format("Key \"%s\" is not a public-private key pair", keyAlias));
        }
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(keyAlias);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document document;
        try (InputStream xmlInputStream = Files.newInputStream(Path.of(xmlFile))) {
            document = dbf.newDocumentBuilder().parse(xmlInputStream);
        }

        Element nodeToSign = (Element) document.getElementsByTagNameNS(XML_ELEMENT_XMLNS, XML_ELEMENT_NAME).item(0);
        nodeToSign.setIdAttribute("ID", true);

        Node signatureNode = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
        if (signatureNode != null) {
            signatureNode.getParentNode().removeChild(signatureNode);
        }

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

        Reference reference = signatureFactory.newReference(
                "#" + nodeToSign.getAttributes().getNamedItem("ID").getNodeValue(),
                signatureFactory.newDigestMethod(DigestMethod.SHA512, null),
                List.of(
                        signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        signatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)
                        ),
                null,
                null
        );

        SignedInfo signedInfo = signatureFactory.newSignedInfo(
                signatureFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE,
                        (C14NMethodParameterSpec) null
                ),
                signatureFactory.newSignatureMethod(SignatureMethod.ECDSA_SHA512, null),
                List.of(reference)
        );

        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(certificate));
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(List.of(x509Data));

        DOMSignContext signContext = new DOMSignContext(privateKey, nodeToSign, nodeToSign.getFirstChild());
        signContext.setDefaultNamespacePrefix("ds");

        XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(signContext);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "s");
        try (OutputStream xmlOutputStream = Files.newOutputStream(Path.of(xmlFile))) {
            trans.transform(new DOMSource(document), new StreamResult(xmlOutputStream));
        }
    }

    @SneakyThrows
    private static @NotNull KeyStore loadKeyStore(String keystoreFile, String keystorePassword) {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (InputStream keystoreInputStream = Files.newInputStream(Path.of(keystoreFile))) {
            keystore.load(keystoreInputStream, keystorePassword.toCharArray());
        }
        return keystore;
    }
}
