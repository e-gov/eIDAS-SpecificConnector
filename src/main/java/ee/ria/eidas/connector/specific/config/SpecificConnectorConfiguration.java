package ee.ria.eidas.connector.specific.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.FileUrlResource;
import org.springframework.util.Assert;

import java.io.File;
import java.net.MalformedURLException;

@Configuration
@ConfigurationPropertiesScan
public class SpecificConnectorConfiguration {

    @Bean
    public static PropertySourcesPlaceholderConfigurer properties(
            @Value("#{environment.SPECIFIC_CONNECTOR_CONFIG_REPOSITORY}/specificCommunicationDefinitionConnector.xml")
                    String specificCommunicationConfig,
            @Value("#{environment.EIDAS_CONFIG_REPOSITORY}/eidas.xml") String eidasConfig) throws MalformedURLException {

        Assert.isTrue(new File(specificCommunicationConfig).exists(), "Required configuration file not found: " + specificCommunicationConfig);
        Assert.isTrue(new File(eidasConfig).exists(), "Required configuration file not found: " + eidasConfig);
        PropertySourcesPlaceholderConfigurer ppc = new PropertySourcesPlaceholderConfigurer();
        ppc.setLocations(new FileUrlResource(specificCommunicationConfig), new FileUrlResource(eidasConfig));
        ppc.setIgnoreUnresolvablePlaceholders(false);
        return ppc;
    }
}
