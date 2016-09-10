package io.getlime.security.admin.controller;

import com.google.common.collect.Lists;
import io.getlime.powerauth.soap.CreateApplicationResponse;
import io.getlime.powerauth.soap.GetApplicationDetailResponse;
import io.getlime.powerauth.soap.GetApplicationListResponse;
import io.getlime.security.soap.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;

/**
 * Controller related to application and application version management.
 *
 * @author Petr Dvorak
 */
@Controller
public class ApplicationController {

    @Autowired
    private PowerAuthServiceClient client;

    /**
     * Redirect '/' URL to the list of application.
     *
     * @return Redirect view to list of applications.
     */
    @RequestMapping(value = "/")
    public String homePage() {
        return "redirect:/application/list";
    }

    /**
     * Show list of applications.
     *
     * @param model Model with passed parameters.
     * @return "applications" view.
     */
    @RequestMapping(value = "/application/list")
    public String applicationList(Map<String, Object> model) {
        List<GetApplicationListResponse.Applications> applicationList = client.getApplicationList();
        model.put("applications", applicationList);
        return "applications";
    }

    /**
     * Create a new application.
     *
     * @param model Model with passed parameters.
     * @return "applicationCreate" view.
     */
    @RequestMapping(value = "/application/create")
    public String applicationCreate(Map<String, Object> model) {
        return "applicationCreate";
    }

    /**
     * Create a new application version.
     *
     * @param id    Application ID
     * @param model Model with passed parameters.
     * @return "applicationVersionCreate" view.
     */
    @RequestMapping(value = "/application/detail/{id}/version/create")
    public String applicationVersionCreate(@PathVariable Long id, Map<String, Object> model) {
        model.put("applicationId", id);
        return "applicationVersionCreate";
    }

    /**
     * Execute the application create action by calling the SOAP service.
     *
     * @param name Application name.
     * @return Redirect to the new application details.
     */
    @RequestMapping(value = "/application/create/do.submit", method = RequestMethod.POST)
    public String applicationCreateAction(@RequestParam String name) {
        CreateApplicationResponse application = client.createApplication(name);
        return "redirect:/application/detail/" + application.getApplicationId();
    }

    /**
     * Execute the application version create action by calling the SOAP service.
     *
     * @param applicationId Application ID.
     * @param name          Version name.
     * @return Redirect to application detail (application versions are visible there).
     */
    @RequestMapping(value = "/application/detail/{applicationId}/version/create/do.submit", method = RequestMethod.POST)
    public String applicationVersionCreateAction(@PathVariable Long applicationId, @RequestParam String name) {
        client.createApplicationVersion(applicationId, name);
        return "redirect:/application/detail/" + applicationId;
    }

    /**
     * Execute the action that marks application version supported / unsupported.
     *
     * @param version Application version.
     * @param enabled True for supported, False for unsupported
     * @param id      Application ID (path variable), for the redirect purposes
     * @return Redirect to application detail (application versions are visible there).
     */
    @RequestMapping(value = "/application/detail/{id}/version/update/do.submit", method = RequestMethod.POST)
    public String applicationUpdateAction(
            @RequestParam(value = "version", required = false) Long version,
            @RequestParam(value = "enabled") Boolean enabled,
            @PathVariable(value = "id") Long id) {
        if (enabled) {
            client.supportApplicationVersion(version);
        } else {
            client.unsupportApplicationVersion(version);
        }
        return "redirect:/application/detail/" + id;
    }

    /**
     * Show application detail.
     *
     * @param id    Application ID.
     * @param model Model with passed parameters.
     * @return "applicationDetail" view.
     */
    @RequestMapping(value = "/application/detail/{id}")
    public String applicationDetail(@PathVariable(value = "id") Long id, Map<String, Object> model) {
        GetApplicationDetailResponse applicationDetails = client.getApplicationDetail(id);
        model.put("id", applicationDetails.getApplicationId());
        model.put("name", applicationDetails.getApplicationName());
        model.put("masterPublicKey", applicationDetails.getMasterPublicKey());
        model.put("versions", Lists.reverse(applicationDetails.getVersions()));
        return "applicationDetail";
    }

}
