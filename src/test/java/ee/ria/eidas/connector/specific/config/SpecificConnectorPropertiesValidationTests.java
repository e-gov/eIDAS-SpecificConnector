package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SigningMethod;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.validation.beanvalidation.SpringConstraintValidatorFactory;

import javax.annotation.PostConstruct;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.ArrayList;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.annotation.DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD;

@DirtiesContext(classMode = AFTER_EACH_TEST_METHOD)
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {SpecificConnectorConfiguration.class, ResponderMetadataConfiguration.class}, initializers = SpecificConnectorTest.TestContextInitializer.class)
@EnableConfigurationProperties(value = SpecificConnectorProperties.class)
@TestPropertySource(value = "classpath:application-test.properties")
public class SpecificConnectorPropertiesValidationTests {
    private static final SpecificConnectorProperties.ServiceProvider SP_1 = SpecificConnectorProperties.ServiceProvider.builder()
            .id("sp_id_1")
            .entityId("https://sp_metadata_1")
            .keyAlias("sp_key_alias_1")
            .type("public").build();

    private Validator validator;

    @Autowired
    SpecificConnectorProperties specificConnectorProperties;

    @Autowired
    AutowireCapableBeanFactory autowireCapableBeanFactory;

    @PostConstruct
    void setupValidator() {
        ValidatorFactory validatorFactory = Validation.byDefaultProvider()
                .configure()
                .constraintValidatorFactory(new SpringConstraintValidatorFactory(autowireCapableBeanFactory))
                .buildValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @BeforeEach
    void setup() {
        specificConnectorProperties.getResponderMetadata().setSupportedAttributes(new ArrayList<>());
        specificConnectorProperties.getResponderMetadata().setSigningMethods(null);
        specificConnectorProperties.getServiceProviders().clear();
        specificConnectorProperties.getServiceProviders().add(SP_1);
    }

    @Test
    void validationFailsWhen_ServiceProvider_IdNotUnique() {
        specificConnectorProperties.getServiceProviders().add(SpecificConnectorProperties.ServiceProvider.builder()
                .id("sp_id_1")
                .entityId("https://sp_metadata_2")
                .keyAlias("sp_key_alias_2")
                .type("public").build());
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("Service provider not unique", constraintViolation.getMessage());
        assertEquals("serviceProviders.id", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_ServiceProvider_EntityIdNotUnique() {
        specificConnectorProperties.getServiceProviders().add(SpecificConnectorProperties.ServiceProvider.builder()
                .id("sp_id_2")
                .entityId("https://sp_metadata_1")
                .keyAlias("sp_key_alias_2")
                .type("public").build());
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("Service provider not unique", constraintViolation.getMessage());
        assertEquals("serviceProviders.entityId", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_ServiceProvider_KeyAliasNotUnique() {
        specificConnectorProperties.getServiceProviders().add(SpecificConnectorProperties.ServiceProvider.builder()
                .id("sp_id_2")
                .entityId("https://sp_metadata_2")
                .keyAlias("sp_key_alias_1")
                .type("public").build());
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("Service provider not unique", constraintViolation.getMessage());
        assertEquals("serviceProviders.keyAlias", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_SupportedAttributes_UnsupportedByName() {
        specificConnectorProperties.getResponderMetadata().getSupportedAttributes()
                .add(SupportedAttribute.builder()
                        .name("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifierUnknown")
                        .friendlyName("PersonIdentifier")
                        .build());
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("eIDAS Attribute not supported", constraintViolation.getMessage());
        assertEquals("responderMetadata.supportedAttributes[0].name", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_SupportedAttributes_UnsupportedByFriendlyName() {
        specificConnectorProperties.getResponderMetadata().getSupportedAttributes()
                .add(SupportedAttribute.builder()
                        .name("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier")
                        .friendlyName("PersonIdentifierUnknown")
                        .build());
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("eIDAS Attribute not supported", constraintViolation.getMessage());
        assertEquals("responderMetadata.supportedAttributes[0].friendlyName", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_SigningMethod_MinKeySizeGreaterThanMaxKeySize() {
        specificConnectorProperties.getResponderMetadata()
                .setSigningMethods(asList(SigningMethod.builder()
                        .name("signatureAlgorithm")
                        .minKeySize(512)
                        .maxKeySize(384).build()));
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("minKeySize <= maxKeySize", constraintViolation.getMessage());
        assertEquals("responderMetadata.signingMethods[0].minKeySize", constraintViolation.getPropertyPath().toString());
    }

    @Test
    void validationFailsWhen_HsmNotEnabled_AndKeyPasswordNotSet() {
        specificConnectorProperties.getHsm().setEnabled(false);
        specificConnectorProperties.getResponderMetadata().setKeyPassword(null);
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("'eidas.connector.responder-metadata.key-password' property must be set if 'eidas.connector.hsm.enabled=false'", constraintViolation.getMessage());
    }

    @Test
    void validationFailsWhen_HsmEnabled_AndSlotNotSetAndSlotIndexIsSet() {
        specificConnectorProperties.getHsm().setEnabled(true);
        specificConnectorProperties.getHsm().setLibrary("/");
        specificConnectorProperties.getHsm().setPin("1234");
        specificConnectorProperties.getHsm().setSlot(null);
        specificConnectorProperties.getHsm().setSlotListIndex(null);
        ConstraintViolation<SpecificConnectorProperties> constraintViolation = validate();
        assertEquals("Invalid HSM configuration", constraintViolation.getMessage());
    }

    @Test
    void validationSucceedsWhen_HsmEnabled_AndSlotIsSet() {
        specificConnectorProperties.getHsm().setEnabled(true);
        specificConnectorProperties.getHsm().setLibrary("/");
        specificConnectorProperties.getHsm().setPin("1234");
        specificConnectorProperties.getHsm().setSlot("0");
        specificConnectorProperties.getHsm().setSlotListIndex(null);
        assertNoValidationErrors();
    }

    @Test
    void validationSucceedsWhen_HsmEnabled_AndSlotListIndexIsSet() {
        specificConnectorProperties.getHsm().setEnabled(true);
        specificConnectorProperties.getHsm().setLibrary("/");
        specificConnectorProperties.getHsm().setPin("1234");
        specificConnectorProperties.getHsm().setSlot(null);
        specificConnectorProperties.getHsm().setSlotListIndex(0);
        assertNoValidationErrors();
    }

    private void assertNoValidationErrors() {
        Set<ConstraintViolation<SpecificConnectorProperties>> constraintViolations = validator.validate(specificConnectorProperties);
        assertTrue(constraintViolations.isEmpty());
    }

    private ConstraintViolation<SpecificConnectorProperties> validate() {
        Set<ConstraintViolation<SpecificConnectorProperties>> constraintViolations = validator.validate(specificConnectorProperties);
        assertEquals(1, constraintViolations.size());
        return constraintViolations.iterator().next();
    }
}
