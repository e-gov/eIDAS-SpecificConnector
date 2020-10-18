package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.exception.AuthenticationException;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadata;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ServiceProviderMetadataRegistry;
import ee.ria.eidas.connector.specific.responder.serviceprovider.ResponseFactory;
import eu.eidas.auth.commons.light.ILightResponse;
import lombok.Data;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.List;

import static org.springframework.web.servlet.View.RESPONSE_STATUS_ATTRIBUTE;

@Slf4j
@Validated
@Controller
public class ConnectorResponseController {

    @Autowired
    private EidasNodeCommunication eidasNodeCommunication;

    @Autowired
    private SpecificConnectorCommunication specificConnectorCommunication;

    @Autowired
    private ServiceProviderMetadataRegistry metadataRegistry;

    @Autowired
    private ResponseFactory responseFactory;

    @GetMapping(value = "/ConnectorResponse")
    public ModelAndView get(@Validated RequestParameters requestParameters, HttpServletRequest request) {
        return execute(requestParameters);
    }

    @PostMapping(value = "/ConnectorResponse")
    public ModelAndView post(@Validated RequestParameters requestParameters, HttpServletRequest request) {
        request.setAttribute(RESPONSE_STATUS_ATTRIBUTE, HttpStatus.TEMPORARY_REDIRECT);
        return execute(requestParameters);
    }

    @SneakyThrows
    private ModelAndView execute(RequestParameters requestParameters) {
        String tokenBase64 = requestParameters.getToken().get(0);
        ILightResponse lightResponse = eidasNodeCommunication.getAndRemoveLightResponse(tokenBase64);
        String metadataEntityId = specificConnectorCommunication.getAndRemoveRequestCorrelation(lightResponse);
        ServiceProviderMetadata spMetadata = metadataRegistry.getByEntityId(metadataEntityId);

        if (lightResponse.getStatus().isFailure()) {
            throw new AuthenticationException("Authentication failed: s%", lightResponse.getStatus().getStatusCode());
        }

        String samlResponseBase64 = responseFactory.createBase64SamlResponse(lightResponse, spMetadata);
        String assertionConsumerServiceUrl = spMetadata.getAssertionConsumerServiceUrl();
        ModelAndView modelAndView = new ModelAndView("redirect:" + assertionConsumerServiceUrl);
        modelAndView.addObject("SAMLResponse", samlResponseBase64); // TODO: Response fails if maxHttpHeaderSize not big enough
        return modelAndView;
    }

    @Data
    public static class RequestParameters {
        @NotNull
        @Size(max = 1, message = "multiple instances of parameter is not allowed")
        private List<@Pattern(regexp = "^[A-Za-z0-9+/=]{1,1000}$", message = "only base64 characters allowed") String> token;
    }
}
