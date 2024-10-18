package ee.ria.eidas.connector.specific.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static java.util.Arrays.stream;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

@Component
@RequiredArgsConstructor
public class RequestCorrelationAttributesTranslationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_NAME_SESSION_ID = "sessionId";
    public static final String MDC_ATTRIBUTE_NAME_VERSION = "serviceVersion";
    public static final String MDC_ATTRIBUTE_CLIENT_IP = "clientIP";
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
        if (isNotEmpty(requestId)) {
            request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestId);
        }

        if (buildProperties != null) {
            MDC.put(MDC_ATTRIBUTE_NAME_VERSION, buildProperties.getVersion());
        }

        String ipAddress = request.getRemoteAddr();
        if (isNotEmpty(ipAddress)) {
            MDC.put(MDC_ATTRIBUTE_CLIENT_IP, ipAddress);
        }

        filterChain.doFilter(request, response);
    }
}
