package ee.ria.eidas.connector.specific.config;

import ee.ria.eidas.connector.specific.SpecificConnectorTest;
import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.SupportedAttribute;
import eu.eidas.auth.commons.attribute.AttributeRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.validation.beanvalidation.SpringConstraintValidatorFactory;

import javax.annotation.PostConstruct;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.List;
import java.util.Set;

import static ee.ria.eidas.connector.specific.config.SpecificConnectorProperties.ResponderMetadata.*;
import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = SpecificConnectorConfiguration.class, initializers = SpecificConnectorTest.TestContextInitializer.class)
@EnableConfigurationProperties(value = SpecificConnectorProperties.class)
@TestPropertySource(value = "classpath:application-test.properties", inheritLocations = false, inheritProperties = false)
public class SpecificConnectorPropertiesDefaultValuesTests {
    private Validator validator;

    @Autowired
    SpecificConnectorProperties specificConnectorProperties;

    @Autowired
    AutowireCapableBeanFactory autowireCapableBeanFactory;

    @Autowired
    AttributeRegistry supportedAttributesRegistry;

    @PostConstruct
    void setupValidator() {
        ValidatorFactory validatorFactory = Validation.byDefaultProvider()
                .configure()
                .constraintValidatorFactory(new SpringConstraintValidatorFactory(autowireCapableBeanFactory))
                .buildValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @BeforeEach
    void validateProperties() {
        validate();
    }

    @Test
    void defaultSupportedAttributes() {
        List<SupportedAttribute> supportedAttributes = specificConnectorProperties.getResponderMetadata().getSupportedAttributes();
        List<String> attibutesByName = supportedAttributes.stream().map(SupportedAttribute::getName).collect(toList());
        List<String> supportedAttibutesByName = supportedAttributesRegistry.getAttributes().stream().map(a -> a.getNameUri().toString()).collect(toList());
        assertThat(attibutesByName).containsExactlyInAnyOrderElementsOf(supportedAttibutesByName);
    }

    @Test
    void defaultDigestMethods() {
        assertThat(specificConnectorProperties.getResponderMetadata().getDigestMethods())
                .containsExactlyInAnyOrderElementsOf(DEFAULT_DIGEST_METHODS);
    }

    @Test
    void defaultSigningMethods() {
        assertThat(specificConnectorProperties.getResponderMetadata().getSigningMethods())
                .containsExactlyInAnyOrderElementsOf(DEFAULT_SIGNING_METHODS);
    }

    @Test
    void defaultSupportedBindings() {
        assertThat(specificConnectorProperties.getResponderMetadata().getSupportedBindings())
                .containsExactlyInAnyOrderElementsOf(DEFAULT_SUPPORTED_BINDINGS);
    }

    @Test
    void defaultSPType() {
        assertEquals("public", specificConnectorProperties.getResponderMetadata().getSpType());
    }

    private void validate() {
        Set<ConstraintViolation<SpecificConnectorProperties>> constraintViolations = validator.validate(specificConnectorProperties);
        assertEquals(0, constraintViolations.size());
    }
}
