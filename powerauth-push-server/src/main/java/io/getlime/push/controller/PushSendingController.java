/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.push.controller;

import io.getlime.push.controller.model.SendBatchMessageRequest;
import io.getlime.push.controller.model.SendMessageResponse;
import io.getlime.push.controller.model.SendPushMessageRequest;
import io.getlime.push.controller.model.StatusResponse;
import io.getlime.push.controller.model.entity.PushMessage;
import io.getlime.push.controller.model.entity.PushSendResult;
import io.getlime.push.service.PushSenderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Controller responsible for processes related to push notification sending.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping(value = "push/message")
public class PushSendingController {

    @Autowired
    private PushSenderService pushSenderService;

    @RequestMapping(value = "send", method = RequestMethod.POST)
    public @ResponseBody SendMessageResponse sendPushMessage(@RequestBody SendPushMessageRequest request) {

        List<PushMessage> pushMessageList = new ArrayList<>();
        pushMessageList.add(request.getPush());
        PushSendResult result = null;
        try {
            result = pushSenderService.send(request.getAppId(), pushMessageList);
        } catch (InterruptedException | IOException e) {
            return returnErrorResponse(result, e);
        }

        SendMessageResponse response = new SendMessageResponse();
        response.setStatus(StatusResponse.OK);
        response.setResult(result);
        return response;
    }

    @RequestMapping(value = "batch/send", method = RequestMethod.POST)
    public @ResponseBody SendMessageResponse sendPushMessage(@RequestBody SendBatchMessageRequest request) {
        PushSendResult result = null;
        try {
            result = pushSenderService.send(request.getAppId(), request.getBatch());
        } catch (InterruptedException | IOException e) {
            return returnErrorResponse(result, e);
        }

        SendMessageResponse response = new SendMessageResponse();
        response.setStatus(StatusResponse.OK);
        response.setResult(result);
        return response;
    }

    private SendMessageResponse returnErrorResponse(PushSendResult result, Exception e) {
        Logger.getLogger(PushSendingController.class.getName()).log(Level.SEVERE, "Error occurred when sending push notifications.", e);
        SendMessageResponse response = new SendMessageResponse();
        response.setStatus(StatusResponse.ERROR);
        response.setResult(result);
        return response;
    }

}
