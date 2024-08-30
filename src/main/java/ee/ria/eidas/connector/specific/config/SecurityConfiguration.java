package ee.ria.eidas.connector.specific.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private SpecificConnectorProperties connectorProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers()
                .contentSecurityPolicy(connectorProperties.getContentSecurityPolicy())
                .and()
                .frameOptions().deny()
                .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(600000);
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            StrictHttpFirewall firewall = new StrictHttpFirewall();
            firewall.setUnsafeAllowAnyHttpMethod(true);
            web.httpFirewall(firewall);
        };
    }
}
