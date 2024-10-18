package ee.ria.eidas.connector.specific.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;

@Component
public class DuplicateRequestParameterFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        Optional<Map.Entry<String, String[]>> duplicateParameter = request.getParameterMap().entrySet().stream().filter(es -> es.getValue().length > 1).findFirst();
        if (duplicateParameter.isPresent()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, format("Duplicate request parameter '%s'", duplicateParameter.get().getKey()));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
