package ee.ria.eidas.connector.specific.exception;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.NotImplementedException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.lang.String.format;

@Slf4j
@ControllerAdvice
public class SpecificConnectorExceptionHandler {
    public static final String BAD_REQUEST_ERROR_MESSAGE = "Bad request exception: %s";

    @ExceptionHandler({BindException.class})
    public ModelAndView handleBindException(BindException ex, HttpServletResponse response) throws IOException {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({BadRequestException.class})
    public ModelAndView handleBadRequestException(BadRequestException ex, HttpServletResponse response) throws IOException {
        log.error(format(BAD_REQUEST_ERROR_MESSAGE, ex.getMessage()));
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    @ExceptionHandler({AuthenticationException.class})
    public ModelAndView handleAuthenticationException(AuthenticationException ex, HttpServletResponse response) throws IOException {
        log.error("AuthenticationException exception", ex);
        throw new NotImplementedException("AuthenticationException handler not implemented");
    }

    @ExceptionHandler({TechnicalException.class})
    public ModelAndView handleTechnicalException(TechnicalException ex, HttpServletResponse response) throws IOException {
        log.error("Technical exception", ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    @ExceptionHandler({Exception.class})
    public ModelAndView handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Unexpected exception", ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }
}