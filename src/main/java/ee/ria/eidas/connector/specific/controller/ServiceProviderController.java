package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.integration.EidasNodeCommunication;
import ee.ria.eidas.connector.specific.integration.SpecificConnectorCommunication;
import ee.ria.eidas.connector.specific.saml.LightRequestFactory;
import eu.eidas.auth.commons.EidasParameterKeys;
import eu.eidas.auth.commons.light.ILightRequest;
import eu.eidas.auth.commons.light.impl.LightRequest;
import eu.eidas.auth.commons.tx.BinaryLightToken;
import eu.eidas.specificcommunication.BinaryLightTokenHelper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URL;

import static org.springframework.web.servlet.View.RESPONSE_STATUS_ATTRIBUTE;

@Slf4j
@Validated
@Controller
public class ServiceProviderController {

    @Autowired
    private SpecificConnectorProperties specificConnectorProperties;

    @Autowired
    private EidasNodeCommunication eidasNodeCommunication;

    @Autowired
    private SpecificConnectorCommunication specificConnectorCommunication;

    @Autowired
    private LightRequestFactory lightRequestFactory;

    @GetMapping(value = "/ServiceProvider")
    public ModelAndView get(@RequestParam("SAMLRequest") String samlRequest,
                            @RequestParam("country") String country,
                            @RequestParam(value = "RelayState", required = false) String relayState) {
        return execute(samlRequest, country, relayState);
    }

    @PostMapping(value = "/ServiceProvider")
    public ModelAndView post(@RequestParam("SAMLRequest") String samlRequest,
                             @RequestParam("country") String country,
                             @RequestParam(value = "RelayState", required = false) String relayState, HttpServletRequest request) {
        request.setAttribute(RESPONSE_STATUS_ATTRIBUTE, HttpStatus.TEMPORARY_REDIRECT);
        return execute(samlRequest, country, relayState);
    }

    @NotNull
    @SneakyThrows
    private ModelAndView execute(String samlRequest, String country, String relayState) {
        ILightRequest lightRequest = lightRequestFactory.createLightRequest(samlRequest, country, relayState);
        BinaryLightToken binaryLightToken = eidasNodeCommunication.putLightRequest(lightRequest);
        specificConnectorCommunication.putRequestCorrelation(lightRequest);
        String token = BinaryLightTokenHelper.encodeBinaryLightTokenBase64(binaryLightToken);
        URL redirectUrl = UriComponentsBuilder.fromUri(URI.create(specificConnectorProperties.getSpecificConnectorRequestUrl()))
                .queryParam(EidasParameterKeys.TOKEN.getValue(), token)
                .build().toUri().toURL();
        return new ModelAndView("redirect:" + redirectUrl);
    }
}
