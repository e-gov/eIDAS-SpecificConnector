package ee.ria.eidas.connector.specific.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

@Component
public class DuplicateRequestParameterFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        Optional<Map.Entry<String, String[]>> duplicateParameter = request.getParameterMap().entrySet().stream().filter(es -> es.getValue().length > 1).findFirst();
        if (duplicateParameter.isPresent()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            String responseBody = format("{\"timestamp\":\"%s\",\"status\":400,\"error\":\"Bad Request\",\"message\":\"Duplicate request parameter '%s'\",\"path\":\"%s\",\"locale\":\"%s\",\"incidentNumber\":\"%s\"}",
                    Instant.now(), duplicateParameter.get().getKey(), request.getRequestURI(), request.getLocale(), MDC.get("traceId"));
            response.getOutputStream().write(responseBody.getBytes(UTF_8));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
