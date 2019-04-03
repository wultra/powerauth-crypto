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
package io.getlime.security.powerauth.crypto.lib.util;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Verify various passwords against Argon2i hashes generated using command line utility.
 */
public class PasswordHashTest {

    @Test
    public void testArgon2Hashes() {
        PasswordHash.verify("".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$VFo3SnVYSnk$WZrqp36HmoSPeGhVCt5Ly3s9pU1OpnRnJMPjnlVcdy8");
        PasswordHash.verify("maC2kBxu".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$YndXNDhGV0o$E2cHqAeGlUyO26haRT/a7VPzcSeLbISimR98F7CAooI");
        PasswordHash.verify("PFhd5jR6".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$VTdEWXFjNVQ$Ejgk/eNZnH6yEbGOUlo/T0fV578oX9B6f+EjeP6iE7I");
        PasswordHash.verify("YYwgb7p8".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$SDdTczlSaFA$hEPOgZDyofKWcpnPEvoSzPVyeuydHFKiB6aK055FA34");
        PasswordHash.verify("EbyBt7U4djF6G84Y".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$UjN6elpVcGI$cRyh9e5nfu6ToXKR1pbPiFudEenRYYuvgea4hvsTB0Y");
        PasswordHash.verify("XhYb2E93LwQeEm9E".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$bVVyNHc2U24$qEkfGgPJ5JzhozbgitvDMgK2Kl8vj7mYvUbjI76NgzE");
        PasswordHash.verify("The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$a3c5RzYzOXo$LLM1F2EBBKjuoUc3CRlPNsmGI3vc3mnvNmafao8askc");
        PasswordHash.verify("Příliš žluťoučký kůň úpěl ďábelské ódy.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$cTZ5NUtYNFg$ma0FJ8SJ/U1YXZ4pmtOMgF23WfodzNEIizke8zG+Auc");
        PasswordHash.verify("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".getBytes(StandardCharsets.UTF_8),
                "$argon2i$v=19$m=32768,t=3,p=16$eTZQV0NuVWU$Xi8HXgnunRNBRjH+U5mXEUC7b9uX1JnWVYZtHMzQYmg");
    }

}
