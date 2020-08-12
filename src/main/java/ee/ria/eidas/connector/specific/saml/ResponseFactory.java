package ee.ria.eidas.connector.specific.saml;

import com.google.common.collect.ImmutableSet;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.exception.TechnicalException;
import ee.ria.eidas.connector.specific.metadata.MetadataSigner;
import ee.ria.eidas.connector.specific.metadata.ServiceProviderMetadata;
import eu.eidas.auth.commons.attribute.AttributeValue;
import eu.eidas.auth.commons.attribute.*;
import eu.eidas.auth.commons.light.ILightResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.opensaml.saml.common.SAMLVersion.VERSION_20;

@Slf4j
@Component
public class ResponseFactory {

    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Autowired
    private MetadataSigner metadataSigner;

    @Autowired
    private String specificConnectorIP;

    private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    public String createBase64SamlResponse(ILightResponse lightResponse, ServiceProviderMetadata spMetadata) {
        try {
            Response response = createResponse(lightResponse, spMetadata);
            metadataSigner.sign(response);
            return serializeResponse(response);
        } catch (Exception ex) {
            throw new TechnicalException("Unable to create SAML Response", ex);
        }
    }

    private Response createResponse(ILightResponse lightResponse, ServiceProviderMetadata spMetadata) throws EncryptionException,
            AttributeValueMarshallingException, SecurityException, MarshallingException, SignatureException, ResolverException {
        Response response = new ResponseBuilder().buildObject();
        response.setDestination(spMetadata.getAssertionConsumerServiceUrl());
        response.setID(secureRandomIdGenerator.generateIdentifier());
        response.setInResponseTo(lightResponse.getInResponseToId());
        response.setIssueInstant(new DateTime());
        response.setVersion(VERSION_20);
        response.setIssuer(createIssuer());
        response.setStatus(createStatus(lightResponse));
        response.setID(lightResponse.getId());
        response.getEncryptedAssertions().add(createAssertion(lightResponse, response.getIssueInstant(), spMetadata));
        return response;
    }

    private EncryptedAssertion createAssertion(ILightResponse lightResponse, DateTime issueInstant, ServiceProviderMetadata spMetadata)
            throws AttributeValueMarshallingException, MarshallingException, SecurityException, SignatureException, ResolverException,
            EncryptionException {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setIssuer(createIssuer());
        assertion.setIssueInstant(issueInstant);
        assertion.setSubject(createSubject(lightResponse, spMetadata.getAssertionConsumerServiceUrl(), issueInstant));
        assertion.getAttributeStatements().add(createAttributeStatement(lightResponse));
        assertion.getAuthnStatements().add(createAuthnStatement(issueInstant, lightResponse.getLevelOfAssurance()));
        assertion.setConditions(createConditions(issueInstant, spMetadata));
        if (spMetadata.getWantAssertionsSigned()) {
            metadataSigner.sign(assertion);
        }
        return spMetadata.encrypt(assertion);
    }

    private Issuer createIssuer() {
        Issuer responseIssuer = new IssuerBuilder().buildObject();
        responseIssuer.setValue(connectorProperties.getMetadata().getEntityId());
        responseIssuer.setFormat(NameIDType.ENTITY);
        return responseIssuer;
    }

    private String serializeResponse(Response response) throws MarshallingException {
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Element responseElement = marshallerFactory.getMarshaller(response).marshall(response);
        String samlResponse = SerializeSupport.nodeToString(responseElement);
        return Base64.getEncoder().encodeToString(samlResponse.getBytes());
    }

    private Status createStatus(ILightResponse lightResponse) {
        String statusCodeUri = lightResponse.getStatus().getStatusCode();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(statusCodeUri);
        Status status = new StatusBuilder().buildObject();
        status.setStatusCode(statusCode);
        return status;
    }

    @SuppressWarnings("unchecked")
    private AttributeStatement createAttributeStatement(ILightResponse lightResponse) throws AttributeValueMarshallingException {
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
        ImmutableAttributeMap responseAttributes = lightResponse.getAttributes();

        for (Map.Entry<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> entry : responseAttributes.getAttributeMap().entrySet()) {
            attributeStatement.getAttributes().add(createAttribute(entry));
        }
        return attributeStatement;
    }

    @SuppressWarnings("unchecked")
    private Attribute createAttribute(Map.Entry<AttributeDefinition<?>, ImmutableSet<? extends AttributeValue<?>>> entry)
            throws AttributeValueMarshallingException {
        AttributeDefinition<?> definition = entry.getKey();
        ImmutableSet<? extends AttributeValue<?>> values = entry.getValue();
        Attribute attribute = createAttribute(definition.getFriendlyName(), definition.getNameUri().toString());
        List<XMLObject> attributeValues = attribute.getAttributeValues();
        AttributeValueMarshaller<?> attributeValueMarshaller = definition.getAttributeValueMarshaller();

        for (AttributeValue<?> attributeValue : values) {
            String value = attributeValueMarshaller.marshal((AttributeValue) attributeValue);
            attributeValues.add(createAttributeValue(definition.getXmlType().toString(), value));
        }
        return attribute;
    }

    private Subject createSubject(ILightResponse lightResponse, String assertionConsumerServiceUrl, DateTime issueInstant) {
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameID = new NameIDBuilder().buildObject();
        nameID.setValue(lightResponse.getSubject());
        nameID.setFormat(NameIDType.UNSPECIFIED); // TODO: Correct?
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setAddress(specificConnectorIP);
        subjectConfirmationData.setInResponseTo(lightResponse.getInResponseToId());
        subjectConfirmationData.setNotOnOrAfter(issueInstant.plusMinutes(5)); // TODO: Make it configurable
        subjectConfirmationData.setRecipient(assertionConsumerServiceUrl);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }

    private Conditions createConditions(DateTime issueInstant, ServiceProviderMetadata spMetadata) {
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plusMinutes(5)); // TODO: Make it configurable

        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI(spMetadata.getEntityId());

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AuthnStatement createAuthnStatement(DateTime issueInstant, String levelOfAssurance) {
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(issueInstant);

        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef(levelOfAssurance);
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        AuthnContextDecl authnContextDecl = new AuthnContextDeclBuilder().buildObject();
        authnContext.setAuthnContextDecl(authnContextDecl);
        authnStatement.setAuthnContext(authnContext);
        return authnStatement;
    }

    private Attribute createAttribute(String friendlyName, String name) {
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setFriendlyName(friendlyName);
        attribute.setName(name);
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri"); // TODO: Find constant
        return attribute;
    }

    private XSAny createAttributeValue(String xsiType, String value) {
        XSAny attributevalue = new XSAnyBuilder().buildObject(org.opensaml.saml.saml2.core.AttributeValue.DEFAULT_ELEMENT_NAME);
        attributevalue.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"), xsiType);
        attributevalue.setTextContent(value);
        return attributevalue;
    }
}
