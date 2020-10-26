package ee.ria.eidas.connector.specific.security;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Arrays.stream;

@Component
@RequiredArgsConstructor
public class RequestCorrelationAttributesTranslationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_NAME_SESSION_ID = "sessionId";
    public static final String MDC_ATTRIBUTE_NAME_VERSION = "serviceVersion";
    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";
    private final BuildProperties buildProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getCookies() != null) {
            stream(request.getCookies()).filter(
                    c -> c.getName().equals("JSESSIONID") // TODO: Configurable
            ).findFirst().ifPresent(c -> MDC.put(MDC_ATTRIBUTE_NAME_SESSION_ID, c.getValue()));
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve
        String requestId = MDC.get("traceId");
        if (StringUtils.isNotEmpty(requestId)) {
            request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestId);
        }

        if (buildProperties != null) {
            MDC.put(MDC_ATTRIBUTE_NAME_VERSION, buildProperties.getVersion());
        }

        filterChain.doFilter(request, response);
    }
}