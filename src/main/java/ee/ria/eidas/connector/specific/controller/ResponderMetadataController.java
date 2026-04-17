package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataGenerator;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.io.MarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;

@Slf4j
@Controller
public class ResponderMetadataController {

    @Autowired
    private ResponderMetadataGenerator responderMetadataGenerator;

    @GetMapping(value = "${eidas.connector.responder-metadata.path:/ConnectorResponderMetadata}", produces = {"application/xml", "text/xml"})
    public void metadata(HttpServletRequest request, HttpServletResponse response) throws MarshallingException, IOException {
        String metadata = OpenSAMLUtils.getXmlString(responderMetadataGenerator.createSignedMetadata());
        log.info("Metadata requested");
        response.setContentType("application/xml");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(metadata);
    }
}
