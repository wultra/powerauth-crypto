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

import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.SharedSecretRequestPqc;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.SharedSecretResponsePqc;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
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

    private static final PqcKemKeyConvertor PQC_KEM_KEY_CONVERTOR = new PqcKemKeyConvertor();

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

    @Test
    public void testGenerateFullKemForClientPrivateKey() throws Exception {
        SharedSecretPqc sharedSecretPqc = new SharedSecretPqc();
        String clientPrivateKey = "MIIJeAIBADALBglghkgBZQMEBAIEgglkBIIJYCx4TdbRH2Xazd2BpTfyIkFqYnlJwk3AutnMG4KSLd/Xxhkjtb2Ik24gZKL1XIMcW17Ai1BEJAa7FA63DCtJz+EWfU/GnfvaGHdyS8ARvuW0V+9CbExRXpdyO4CzBNoyaOVQvZ48wfXxA6yjzQGnw527MGI6Tx67ktiMu8lVHoapo/wkHrg8wERCVUuIAtgEOdcVkM8jeSXIhadslKGRfCU2P2RzoY1KJeBRZfUjhQZTq9RDQdbpg3dglZ1JtHQlE6nEENrFm5sxPoxExTy4CAbDJaiSeNiMsCvnpyFywxGLq2gnxKpwYTM2fz/3xwiavtu2s3G0rHOYCICKQgrIHO0Aj+nDXo+cI48yMZiMUdmjq6kEIB+hskd2CIzgYjlFmRECkAcDFgc1mpt5Aap2YMdLFLQEVG66PWfLyOQLanNMkT6Vt9bHn99KwsPcJ89KHP3InqXbE+PiJ5mrda+riKSiQtwovqx0VyZmJJxglGEqWRkIVwZIQFkLQPvmW4v2K74VzOvFFdqHGy3yc4jBZRtxWKwBBVVHyL2QEHfnbrKZcFgTKiTisKgjVECsmc+BWwJYN+qsyQXbZz/RI4L2vI3EmQBlz75RvE+UxdvxaWR0QV2ALbKhj9T6puMMhNhBxzH6eRKcTkNFaa7gceards4nWJzUJ4FMllUZUdnJSVhHYZ1AsNM3LaVRT7dgDeG7IESTvvdxZdwAtcYHyskQG3XgcypADDNDWSbDtP4lfU3aqOOHEoX4yCWADY+EoCkrrYPVdqkmQnXmxYqnOGYCTR98FGVbZzEhPddpvK52OBCjGwRbpPn5j41rjGRxmaUwx4/FPdOLqXWwEbnMthPxxopotMZhcm8xX63FKNswqvtMEOrJXv03UdKjDkdXMMwIuoagAfYwRTSlgljVBjGzxsJaONfcm0F7WCbVX7NhuJuEYqtDsRF7ABw2oYLJitTbKfTcx/hzh/FgmGl0eVTYYzGnADJWq7OooVFrHE5DioPRORy4bkTDjNS0h7p2aqqCzv4Thr0pQAVSntSFu6VQfZ+KU1o8QX7Ksx6Rf/ODNr22Dm62F/S7wvPJPwihxFuaF6KMXre2cGxqxLEFr0wgZE2YUsT4K6dsH05bRqwgXOhpFJmMwzBLMSDJzB0YehPLfeA1gUHreJ2TtKlxJTApkGM4iV0pIDaCwyQrgWa7l7hRXD+nIl88JJ5hmeQ1DHMjSDzjwoBCQUpFbRr7WrpxJ3PpuYEBjAbVPt5DSloRhxMsFQMnPgDxQSn8tWrgzGA7nAx4dc3Mh1AQEFdjMVQTkSmxWHFCtikLLrUXGirRbl00gPyTESIgTCoFrt3bwRABslfas7czcauRHR5YXJX6a0GHsHnwS/6bXEX5R8aCp0E0PzAkJT7MnKFLdjh0kYFbZNWkL/HEYPUsEpsRPlxai5TInM3MhJfBUBGgOTspXiPbAvbcnOKwTj2Ty8QRfLipL8n1o2bcPabXNGUIYoubVCKxqxxxD8O6GcLYASlAvXlgVK7AeLXmzFSBg6yjr6f6ntl8LXyrl7KwcSBCXKsyZeZadnIHTQDhQKrlDPekvpcyYqL8GwCplvUCz5WJqqSKsLspJwNLWxdgb2/3R8LAwdRzRN4hZkVRYrRqPGULWGYGoBuaSS+7qcs4FuSys9BMxj9rRm2lzAbVG/5Jyf67PpikcFJMAdOpB1Q7Aj3AJhKQphkMWYuBKIybEXU6KGMHnFhrR2mVZX05RWJlPHjiuG5Vnrily9C4VE+VFu4ix2VaI4OSE67JcRdAm9eEpM70jjPlgcHFo+BXySlIoLvJko73atn8vc2mkA7gMJanQnWRAv16lA26d+dxE1W5JOagXx4hXpcAZN4rB0WlxRlQaGdmXgG3mBNZkqg5KrGAhH7ac3pghCUGJIxGPf2yOemlKGnKu2xoppMhPFF4EFPMZMQMS9XsvXpmd+nwrDykEQRXJzgwv+AVS8bFaQr3Lw1VmssWglixsUf0B1GXDv7xlvn6oX/Xn3xrDrT8CtY5mZ+bhZRaXH9zGA8XTuqicUeywN2szE9MwPwZUUMnu8R4NtDoZQSWGKlGfTbmypF6eXAHKAV6H7YxMixAWZ2rEpOjB7urb7JBt+0RD+boYoCXmhVxEedcytVXXrLxZ9XBEqVXFB1nzwfRsy8bLgrXFQqjKtOxY6hHyjvjsG+mjRHESLrofzSEt6EyGb4cYKiXFtnFfo9jUr6MxAIySZpKdgbUITYyY9Zmtho2YwJIBqxqwBa4tt1LouzKzx+wB4ILMpiFm3njvBDSJRRlyQyBiKEyxC2WsilnW6bkadoGz3okc4DwdSlgkFH1I53kWuwipCgDYwDRdy+hQ/uhuwbGkqoxeGQqnu7hnaa8SVTWp923t9pVzuSkzc6kRzFRFWiZHtnmLoRTzsgsaPvWXUvTKwSJf1ZkCMUUySm7OH7jjpdLi5wUNTfivvq8O+HKtJ1WQ7eUQveAYfimJfFpA1tULrQqtvyqsIbYGaGkk6xVyp+Iq5FFjQQwAJgrGgZXusHqo9z0jHPwZZLqwo9CiSUrJaLUguK3gzCyMxBZvhHpSzmaLBSguQaFjWnIzGpAnuehhfVRBBw7l/qEBXr2C79HJ65wu5GsGLV3uk53X8wrRB6IQrzbtAALEJQCJboUXnnFIURkQ9EWhUL4MQqoRgUFkxizfywDIK1VOy9cM74Dk/drdWXBM/CZXgzmp40rv/6bUkvlza7GttrsLDRzkYyDV3OSenHKwWZ1bAWWapZYrVurar/QWNfqteYsQDwQxlJQbEyZRcbgSZ0GYOQ1kaipvp2KNfWzP8+pUEirAstVEM71lrCLvztLru1xGg5pzdATOa5KEy4lVv3GY2BAqAXMM/Cnn9sqBKNCsgPDv+JYlWtwQmFaNADpa8vWfVbhZaDCG8VEP0PXRD5lN6PhDsS0ODlkSAv2sEH8dr0iVMxkHgK0Qib1FlYQaPH4cQwwUuRrzYJqofsAOdDMEoI1KOV6Nv8gzSoIEhlBQ1Oyq7k4vL8wIdBbsLhWyMS7wdtiFTmqH6bWRZo1h1jGPEXxIkQXBwilFH1wyHhMMoRIlTJTSW0QcdKqcc7nkBKCLxwuOqbp6BvMwMeYZ6uANK7rnnCSGSutc16d6vpsi1Zr+i9gVtHC3zfAwrJbdz83eSp4rEsen5ZCzRkuAJZJaEkA+JhvO8JxLA==";
        BCMLKEMPrivateKey privateKey = (BCMLKEMPrivateKey) PQC_KEM_KEY_CONVERTOR.convertBytesToPrivateKey(Base64.getDecoder().decode(clientPrivateKey));
        String requestEncapsulationKey = Base64.getEncoder().encodeToString(PQC_KEM_KEY_CONVERTOR.convertPublicKeyToBytes(privateKey.getPublicKey()));
        SharedSecretRequestPqc clientRequest = new SharedSecretRequestPqc(requestEncapsulationKey);
        ResponseCryptogram serverResponse = sharedSecretPqc.generateResponseCryptogram(clientRequest);
        assertNotNull(serverResponse.getSecretKey());
        assertNotNull(serverResponse.getSharedSecretResponse());
        System.out.println("req = " + requestEncapsulationKey);
        System.out.println("ct  = " + ((SharedSecretResponsePqc) serverResponse.getSharedSecretResponse()).getPqcCiphertext());
        System.out.println("ss  = " + (Base64.getEncoder().encodeToString(serverResponse.getSecretKey().getEncoded())));
    }

}
