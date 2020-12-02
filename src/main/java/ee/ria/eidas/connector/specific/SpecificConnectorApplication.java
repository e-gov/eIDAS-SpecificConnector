package ee.ria.eidas.connector.specific;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.util.Assert;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SpecificConnectorApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        Assert.notNull(System.getenv("EIDAS_CONFIG_REPOSITORY"), "Required environment variable EIDAS_CONFIG_REPOSITORY is not set");
        Assert.notNull(System.getenv("SPECIFIC_CONNECTOR_CONFIG_REPOSITORY"), "Required environment variable SPECIFIC_CONNECTOR_CONFIG_REPOSITORY is not set");
        SpringApplication.run(SpecificConnectorApplication.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(SpecificConnectorApplication.class).properties("server.error.whitelabel.enabled=false");
    }
}
