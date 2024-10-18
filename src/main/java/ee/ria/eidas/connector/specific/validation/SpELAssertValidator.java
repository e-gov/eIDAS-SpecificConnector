package ee.ria.eidas.connector.specific.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import static org.apache.commons.lang.BooleanUtils.isTrue;

@Slf4j
@RequiredArgsConstructor
public class SpELAssertValidator implements ConstraintValidator<SpELAssert, Object> {
    private final AutowireCapableBeanFactory beanFactory;
    private Expression expression;
    private SpELAssert anntoation;

    @Override
    public void initialize(SpELAssert constraintAnnotation) {
        expression = new SpelExpressionParser().parseExpression(constraintAnnotation.value());
        anntoation = constraintAnnotation;
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        if (value == null) return true;

        boolean isValid = isTrue(expression.getValue(createEvaluationContext(value), Boolean.class));
        if (!isValid) {
            addConstraintViolation(context);
        }
        return isValid;
    }

    private StandardEvaluationContext createEvaluationContext(Object rootObject) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setRootObject(rootObject);
        context.setBeanResolver(new BeanFactoryResolver(beanFactory));
        return context;
    }

    private void addConstraintViolation(ConstraintValidatorContext ctx) {
        ctx.buildConstraintViolationWithTemplate(anntoation.message())
                .addPropertyNode(anntoation.appliesTo())
                .addConstraintViolation()
                .disableDefaultConstraintViolation();
    }
}

