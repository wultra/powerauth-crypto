package io.getlime.push.controller;

import io.getlime.push.controller.model.StatusResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Class representing controller used for service and maintenance purpose.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping(value = "push/service")
public class ServiceController {

    /**
     * Basic "hello" controller, used to check the service.
     * @return Basic OK response.
     */
    @RequestMapping(value = "hello")
    public @ResponseBody StatusResponse hello() {
        StatusResponse response = new StatusResponse();
        response.setStatus(StatusResponse.OK);
        return response;
    }

}
