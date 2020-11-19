package ee.ria.eidas.connector.specific.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    public static final String POST_BINDING_SUBMIT_SCRIPT = "'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='";
    public static final String CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self' " + POST_BINDING_SUBMIT_SCRIPT;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .headers()
                .contentSecurityPolicy(CONTENT_SECURITY_POLICY)
                .and()
                .frameOptions().deny()
                .httpStrictTransportSecurity()
                .includeSubDomains(true)
                .maxAgeInSeconds(600000);
    }

    @Override
    public void configure(WebSecurity webSecurity) {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setUnsafeAllowAnyHttpMethod(true);
        webSecurity.httpFirewall(firewall);
    }
}