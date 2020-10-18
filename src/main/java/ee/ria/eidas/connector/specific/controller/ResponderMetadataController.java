package ee.ria.eidas.connector.specific.controller;

import ee.ria.eidas.connector.specific.responder.metadata.ResponderMetadataGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@Controller
public class ResponderMetadataController {

    @Autowired
    private ResponderMetadataGenerator responderMetadataGenerator;

    @GetMapping(value = "${eidas.connector.responder-metadata.path:/ConnectorResponderMetadata}", produces = {"application/xml", "text/xml"})
    @ResponseBody
    public String metadata() {
        return responderMetadataGenerator.createSignedMetadata();
    }
}
