package io.getlime.security.admin.controller;

import io.getlime.powerauth.soap.*;
import io.getlime.security.PowerAuthWebServiceConfiguration;
import io.getlime.security.soap.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;

/**
 * Controller related to integration management.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
public class IntegrationController {

    @Autowired
    private PowerAuthServiceClient client;

    @Autowired
    private PowerAuthWebServiceConfiguration configuration;

    /**
     * Show list of integrations.
     *
     * @param model Model with passed parameters.
     * @return "integrations" view.
     */
    @RequestMapping(value = "/integration/list")
    public String integrationList(Map<String, Object> model) {
        GetIntegrationListRequest request = new GetIntegrationListRequest();
        GetIntegrationListResponse integrationListResponse = client.getIntegrationList(request);
        model.put("restrictedAccess", integrationListResponse.isRestrictedAccess());
        model.put("integrations", integrationListResponse.getItems());
        return "integrations";
    }

    /**
     * Create a new integration.
     *
     * @param model Model with passed parameters.
     * @return "integrationCreate" view.
     */
    @RequestMapping(value = "/integration/create")
    public String integrationCreate(Map<String, Object> model) {
        return "integrationCreate";
    }

    /**
     * Execute the integration create action by calling the SOAP service.
     *
     * @param name Integration name.
     * @return Redirect to the integration list.
     */
    @RequestMapping(value = "/integration/create/do.submit", method = RequestMethod.POST)
    public String integrationCreateAction(@RequestParam String name) {
        client.createIntegration(name);
        return "redirect:/integration/list";
    }

    /**
     * Remove integration.
     *
     * @param integrationId Integration ID
     * @param model         Model with passed parameters.
     * @return Redirect user to given URL or to activation detail, in case 'redirect' is null or empty.
     */
    @RequestMapping(value = "/integration/remove/do.submit", method = RequestMethod.POST)
    public String removeActivation(@RequestParam(value = "integrationId") String integrationId, Map<String, Object> model) {
        if (!configuration.isCurrentSecuritySettings(integrationId)) {
            client.removeIntegration(integrationId);
        }
        return "redirect:/integration/list";
    }

}
