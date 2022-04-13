package ee.ria.eidas.connector.specific.util;

import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.light.impl.LightResponse;
import eu.eidas.auth.commons.light.impl.ResponseStatus;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.jetbrains.annotations.NotNull;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.impl.ResponseImpl;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.DigestAlgorithm;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.algorithm.descriptors.DigestSHA512;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.util.ResourceUtils;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static eu.eidas.auth.commons.protocol.eidas.spec.NaturalPersonSpec.Definitions.*;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.springframework.util.ResourceUtils.getFile;

@UtilityClass
public class TestUtils {
    public static final String UUID_REGEX = "[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}";
    public static final String SECURE_RANDOM_REGEX = "^[_].{64}$";
    public static final String SHA512_REGEX = "^[0-9a-fA-F]{128}$";

    public Status getStatus(String samlResponseBase64) throws XMLParserException, UnmarshallingException {
        return getResponse(samlResponseBase64).getStatus();
    }

    public ResponseImpl getResponse(String samlResponseBase64) throws XMLParserException, UnmarshallingException {
        byte[] decodedSamlResponse = Base64.getDecoder().decode(samlResponseBase64);
        return (ResponseImpl) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(decodedSamlResponse));
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

    public LightResponse createLightResponse(ILightRequest lightRequest) {
        ResponseStatus responseStatus = ResponseStatus.builder()
                .statusMessage("statusMessage")
                .statusCode("statusCode")
                .subStatusCode("subStatusCode")
                .failure(false)
                .build();

        LightResponse lightResponse = LightResponse.builder()
                .id("_7.t.B2GE0lkaDDkpvwZJfrdOLrKQqiINw.0XnzAEucYP7yO7WVBC_hR2kkQ-hwy")
                .inResponseToId(lightRequest.getId())
                .status(responseStatus)
                .subject("assertion_subject")
                .subjectNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                .levelOfAssurance("http://eidas.europa.eu/LoA/high")
                .issuer("https://eidas-specificconnector:8443/EidasNode/ConnectorMetadata")
                .build();
        return lightResponse;
    }

    public LightResponse createLightResponse(LightRequest lightRequest, ResponseStatus responseStatus) {
        ImmutableAttributeMap requestedAttributes = ImmutableAttributeMap.builder()
                .put(PERSON_IDENTIFIER, "123456789")
                .put(CURRENT_FAMILY_NAME, "TestFamilyName")
                .put(CURRENT_GIVEN_NAME, "TestGivenName")
                .put(DATE_OF_BIRTH, "1965-01-01").build();
        return LightResponse.builder()
                .id("_7.t.B2GE0lkaDDkpvwZJfrdOLrKQqiINw.0XnzAEucYP7yO7WVBC_hR2kkQ-hwy")
                .inResponseToId(lightRequest.getId())
                .status(responseStatus)
                .subject("assertion_subject")
                .subjectNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                .levelOfAssurance(lightRequest.getLevelOfAssurance())
                .issuer("https://eidas-specificconnector:8443/EidasNode/ConnectorMetadata")
                .attributes(requestedAttributes)
                .relayState(lightRequest.getRelayState())
                .build();
    }

    @SneakyThrows
    public String getSignedSamlAsBase64(SignableSAMLObject samlObject) {
        SignableSAMLObject signedSamlObject = getSignedSamlObject(samlObject);
        Element xmlObject = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signedSamlObject).marshall(signedSamlObject);
        String signedXml = SerializeSupport.nodeToString(xmlObject);
        return Base64Support.encode(signedXml.getBytes(), false);
    }

    @SneakyThrows
    public SignableSAMLObject getSignedSamlObject(SignableSAMLObject samlObject) {
        Credential signingCredential = setupSigningCredential();
        Signature signature = (Signature) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);
        String signatureAlgorithmUri = getSignatureAlgorithm(signingCredential);
        SignatureAlgorithm signatureAlgorithm = OpenSAMLUtils.getSignatureAlgorithm(signatureAlgorithmUri);
        setSignatureHashToSHA512(samlObject, signingCredential, signature, signatureAlgorithm);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(samlObject).marshall(samlObject);
        Signer.signObject(signature);
        return samlObject;
    }

    private void setSignatureHashToSHA512(SignableSAMLObject samlObject, Credential signingCredential, Signature signature, SignatureAlgorithm signatureAlgorithm) throws org.opensaml.security.SecurityException {
        DigestAlgorithm digestAlgorithm = new DigestSHA512();
        SignatureSigningParameters params = getSignatureSigningParameters(signingCredential, signatureAlgorithm, digestAlgorithm);
        SignatureSupport.prepareSignatureParams(signature, params);
        samlObject.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm.getURI());
    }

    @SneakyThrows
    private Credential setupSigningCredential() {
        File spMetadataKeystore = ResourceUtils.getFile("classpath:__files/mock_keys/service-provider-metadata-keystore.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(spMetadataKeystore)) {
            keyStore.load(fis, "changeit".toCharArray());
            return getCredential(keyStore, "service-provider-request-signing", "changeit");
        }
    }

    @SneakyThrows
    private Credential getCredential(KeyStore keystore, String keyPairId, String privateKeyPass) {
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(keyPairId, privateKeyPass);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
        Criterion criterion = new EntityIdCriterion(keyPairId);
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(criterion);
        return resolver.resolveSingle(criteriaSet);
    }

    private String getSignatureAlgorithm(Credential credential) {
        String algorithmUrl = null;
        String algorithm = ((BasicX509Credential) credential).getEntityCertificate().getSigAlgName().toUpperCase();
        switch (algorithm) {
            case "SHA256WITHECDSA":
                algorithmUrl = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256;
                break;
            case "SHA1WITHECDSA":
                algorithmUrl = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
                break;
            case "SHA384WITHECDSA":
                algorithmUrl = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384;
                break;
            case "SHA512WITHECDSA":
                algorithmUrl = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512;
                break;
            case "SHA256WITHRSA":
                algorithmUrl = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
                break;
        }
        return algorithmUrl;
    }

    private SignatureSigningParameters getSignatureSigningParameters(Credential credential, SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm) {
        SignatureSigningParameters params = new SignatureSigningParameters();
        params.setSigningCredential(credential);
        params.setSignatureAlgorithm(signatureAlgorithm.getURI());
        params.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        params.setSignatureReferenceDigestMethod(digestAlgorithm.getURI());
        params.setKeyInfoGenerator(getX509KeyInfoGenerator());
        return params;
    }

    private KeyInfoGenerator getX509KeyInfoGenerator() {
        X509KeyInfoGeneratorFactory x509KeyInfoGenerator = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGenerator.setEmitEntityCertificate(true);
        return x509KeyInfoGenerator.newInstance();
    }
}
