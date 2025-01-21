/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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
package com.wultra.security.powerauth.crypto.lib.util;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Test verification of Argon2 hashes.
 */
public class PasswordHashTest {

    @Test
    public void testArgon2Hashes() throws IOException {
        System.out.println("Testing Argon2 hash verification using various passwords.");
        PasswordHash.verify("".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$VFo3SnVYSnk$WZrqp36HmoSPeGhVCt5Ly3s9pU1OpnRnJMPjnlVcdy8");
        PasswordHash.verify("maC2kBxu".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$YndXNDhGV0o$E2cHqAeGlUyO26haRT/a7VPzcSeLbISimR98F7CAooI");
        PasswordHash.verify("EbyBt7U4djF6G84Y".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$UjN6elpVcGI$cRyh9e5nfu6ToXKR1pbPiFudEenRYYuvgea4hvsTB0Y");
        PasswordHash.verify("The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$a3c5RzYzOXo$LLM1F2EBBKjuoUc3CRlPNsmGI3vc3mnvNmafao8askc");
        PasswordHash.verify("Příliš žluťoučký kůň úpěl ďábelské ódy.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$cTZ5NUtYNFg$ma0FJ8SJ/U1YXZ4pmtOMgF23WfodzNEIizke8zG+Auc");
        PasswordHash.verify("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$eTZQV0NuVWU$Xi8HXgnunRNBRjH+U5mXEUC7b9uX1JnWVYZtHMzQYmg");
    }

    @Test
    public void testArgon2DifferentParameters() throws IOException {
        System.out.println("Testing Argon2 hash verification using various algorithm parameters.");
        PasswordHash.verify("password".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
        PasswordHash.verify("password".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
        PasswordHash.verify("password".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");
        PasswordHash.verify("password".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");
    }

    @Test
    public void testArgon2id() throws IOException {
        System.out.println("Testing Argon2 hash verification using Argon2id algorithm.");
        PasswordHash.verify("password".getBytes(StandardCharsets.UTF_8), "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc");
    }
}
