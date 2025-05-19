/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.wultra.security.powerauth.crypto.lib.v4.sharedsecret;

import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponsePqc;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for generating response on a specific client request which prints out ciphertext and shared secret.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MlKemClientRequestTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateResponseForClientRequest() throws Exception {
        SharedSecretPqc sharedSecretPqc = new SharedSecretPqc();
        String requestEncapsulationKey = "MIIEsjALBglghkgBZQMEBAIDggShAJbJhpVSr6XGxAEiILThojI7z3JLq8/zg/VErUHzAbhKiqjgUigWL+7VH6ILmTKBjapgCrUiGJ3XnaV6xvfluNpLpnTJnmhBPod5hXGzovJCY7pKFNKBAjW0F2NZyOMEiDsUwSajjvRWK9O6at22iXE6sunQPpJhzScQRpMyMjiwyaOkoBHUpOcrfKvBkP5GIeOaFxzAaJdXJmh1mGZVBUTaxndlqaXhMY/afgAnWSrrpGrKv1dIsY3rVov0zcxyIsE5qiULK7XmptCHaoPzNSGcjbPZkDPIwF1xPPCqZgmyfl8UpF7ctqrVvfnbbr+rPd9aA8I5FgYmybhqMifTTouZITPJmPw2NlSbY6JoAg37p3imh6ZQLVG4VzCbCAniOboIVWCxlvh1FKd5Qd12g5jEPbDLlNGKYTJFT0w8qukTHIaXQZHpNIXSINrDnd4LRJHnuFxZK/qQwClAgFWUU8UYtNA4zFOQvACodXGFZD0CoFhpfl4lBxSgqz3CoayrZTK6VsQ3WDQnfCvDKtT2vxNoZnwaRBCGtWn2rxN5noUGLWAQWomoE2RxdVPDWcj5KX2Ulc91rYzmJVUXeWExzbITZ5oZXeo3PEV8tpcmxcPId/KGWxGcfDTIxKdXXUoKoxNDez9yTMjnVyL8YsuEUqAST4a3iMU4UWLZcIlbTrTlI/ExFsU0QRU2gQWSgt5hGBLHYGKARtRQaSHEWo41GMPgRRR6L1alcM+YT22xrca2JpZUdh+Xq3AAkuOpl4uMH0ZTYYF3lqC1OARgUU2DOa4YlG6EUksHiOTMo5qcqX4mpvkQhm+BgKSmYdIjmDhCIt7aMcj6IbSEi5uJwcBqOfOYEpM5KNdTW/4QQVvAsLcxDCEWmGI0oA6mYC1Kw46QvyqlhSLhua44XsxIGq48D+TpfE5KeGq0SQF2CfDwnbKnU/1DG3B2fofsJtonGSZKwlqkRfqGtGcWhfACA5knlIizTYOUcpwFym9MRfFKa7kMNUp2jt5aDNUcF2kAWnELbCm3Qi5pZuxcECpRRod3OLGCeoNYj6+nBK+QajpHiTj2d6iBljl8HCbGbhSctVlqowLcjXVsskAMNc/WeKirR0K6Mr3WG7cyURpxMwYRmDPBOPz3VuO0BmBgVgMXgEySPr68rL1Imqqyyvy0uiBoxDI5nWYDytGQPSToAk1xMJMhmFIkkfeoiowbl9ERR7BHmlLKpPNcFMI3ZX+nNUp7zBdyNp02jkk3KhJCYwDqPWKoJMBAvaEHuAIHEIaxJPGYC6cXlPBLDoewsuwBy9VbaKETB+9EFIHxc1dyiNN2xBxIhdKqP52Uzi0KsiFWe884pFQjxeLTalDyA5asVqB2znhXZ3/BZ6QJBAsFYvypCQVjYxXCRQ31h96bIn6KC8cxKsunOWBKqGVggdPDwkanvP4HtnXsbQwnMkAZTA/7dGYnprumHkWHuidEEAvhBdNWTWoCaqAjWxZEE4kSYUOnoTh4BEYLQ45aTbj0IRKFqCr4jeGnB4ZBo2jhTgRps7KJJeD+NiaS9IvAM9DuvAv/SeuAYv/iBtew78luR9SNGBmW";
        SharedSecretRequestPqc clientRequest = new SharedSecretRequestPqc(requestEncapsulationKey);
        ResponseCryptogram serverResponse = sharedSecretPqc.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse.getSecretKey());
        assertNotNull(serverResponse.getSharedSecretResponse());
        System.out.println("req = " + requestEncapsulationKey);
        System.out.println("ct  = " + ((SharedSecretResponsePqc) serverResponse.getSharedSecretResponse()).getPqcCiphertext());
        System.out.println("ss  = " + (Base64.getEncoder().encodeToString(serverResponse.getSecretKey().getEncoded())));
    }
}
