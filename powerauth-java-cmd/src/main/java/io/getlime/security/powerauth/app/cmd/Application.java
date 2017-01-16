/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.cmd;

import io.getlime.security.powerauth.app.cmd.steps.*;
import io.getlime.security.powerauth.app.cmd.util.ConfigurationUtils;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.net.ssl.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

/**
 * Command-line utility for testing PowerAuth implementation and for verification of
 * a correct system deployment.
 *
 * @author Petr Dvorak
 *
 */
@SpringBootApplication
public class Application implements CommandLineRunner {

    private JSONObject clientConfigObject = null;

    /**
     * Application main
     * @param args Arguments, use --help to print expected arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Override
    public void run(String... args) throws Exception {

        try {

            // Add Bouncy Castle Security Provider
            Security.addProvider(new BouncyCastleProvider());
            PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());

            // Options definition
            Options options = new Options();
            options.addOption("h", "help", false, "Print this help manual.");
            options.addOption("u", "url", true, "Base URL of the PowerAuth 2.0 Standard RESTful API.");
            options.addOption("m", "method", true, "What API method to call, available names are 'prepare', 'status', 'remove', 'sign' and 'unlock',");
            options.addOption("c", "config-file", true, "Specifies a path to the config file with Base64 encoded server master public key, application ID and application secret.");
            options.addOption("s", "status-file", true, "Path to the file with the activation status, serving as the data persistence.");
            options.addOption("a", "activation-code", true, "In case a specified method is 'prepare', this field contains the activation key (a concatenation of a short activation ID and activation OTP).");
            options.addOption("t", "http-method", true, "In case a specified method is 'sign', this field specifies a HTTP method, as specified in PowerAuth signature process.");
            options.addOption("e", "endpoint", true, "In case a specified method is 'sign', this field specifies a URI identifier, as specified in PowerAuth signature process.");
            options.addOption("l", "signature-type", true, "In case a specified method is 'sign', this field specifies a signature type, as specified in PowerAuth signature process.");
            options.addOption("d", "data-file", true, "In case a specified method is 'sign', this field specifies a file with the input data to be signed and verified with the server, as specified in PowerAuth signature process.");
            options.addOption("p", "password", true, "Password used for a knowledge related key encryption. If not specified, an interactive input is required.");
            options.addOption("i", "invalidSsl", false, "Client may accept invalid SSL certificate in HTTPS communication.");

            // Options parsing
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            // Check if help was invoked
            if (cmd.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("java -jar powerauth-java-cmd.jar", options);
                return;
            }

            // Allow invalid SSL certificates
            if (cmd.hasOption("i")) {
                HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });

                TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }};

                try {
                    SSLContext sc = SSLContext.getInstance("SSL");
                    sc.init(null, trustAllCerts, new java.security.SecureRandom());
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                } catch (Exception e) {
                }
            }

            // Read values
            String method = cmd.getOptionValue("m");
            String uriString = cmd.getOptionValue("u");
            String statusFileName = cmd.getOptionValue("s");
            String configFileName = cmd.getOptionValue("c");

            // Read config file
            if (Files.exists(Paths.get(configFileName))) {
                byte[] configFileBytes = Files.readAllBytes(Paths.get(configFileName));
                try {
                    clientConfigObject = (JSONObject) JSONValue.parse(new String(configFileBytes));
                } catch (Exception e) {
                    System.out.println("Config file must be in a correct JSON format");
                    System.out.println();
                    System.out.println("### Failed.");
                    System.out.println();
                    System.exit(1);
                }
            } else {
                System.out.println("Unable to read client config file");
                System.out.println();
                System.out.println("### Failed.");
                System.out.println();
                System.exit(1);
            }

            // Read master public key
            PublicKey masterPublicKey = ConfigurationUtils.getMasterKey(clientConfigObject);

            // Read current activation state from the activation state file or create an empty state
            JSONObject resultStatusObject = null;
            if (Files.exists(Paths.get(statusFileName))) {
                byte[] statusFileBytes = Files.readAllBytes(Paths.get(statusFileName));
                resultStatusObject = (JSONObject) JSONValue.parse(new String(statusFileBytes));
            } else {
                resultStatusObject = new JSONObject();
            }

            // Execute the code for given methods
            if (method.equals("prepare")) {

                Map<String, Object> context = new HashMap<>();
                context.put("URI_STRING", uriString);
                context.put("MASTER_PUBLIC_KEY", masterPublicKey);
                context.put("STATUS_OBJECT", resultStatusObject);
                context.put("STATUS_FILENAME", statusFileName);
                context.put("ACTIVATION_CODE", cmd.getOptionValue("a"));
                context.put("PASSWORD", cmd.getOptionValue("p"));
                context.put("ACTIVATION_NAME", ConfigurationUtils.getApplicationName(clientConfigObject));
                context.put("APPLICATION_ID", ConfigurationUtils.getApplicationKey(clientConfigObject));
                context.put("APPLICATION_SECRET", ConfigurationUtils.getApplicationSecret(clientConfigObject));

                PrepareActivationStep.execute(context);

            } else if (method.equals("status")) {

                Map<String, Object> context = new HashMap<>();
                context.put("URI_STRING", uriString);
                context.put("STATUS_OBJECT", resultStatusObject);

                GetStatusStep.execute(context);

            } else if (method.equals("remove")) {

                Map<String, Object> context = new HashMap<>();
                context.put("URI_STRING", uriString);
                context.put("STATUS_OBJECT", resultStatusObject);
                context.put("STATUS_FILENAME", statusFileName);
                context.put("APPLICATION_ID", ConfigurationUtils.getApplicationKey(clientConfigObject));
                context.put("APPLICATION_SECRET", ConfigurationUtils.getApplicationSecret(clientConfigObject));
                context.put("PASSWORD", cmd.getOptionValue("p"));

                RemoveStep.execute(context);

            } else if (method.equals("sign")) {

                Map<String, Object> context = new HashMap<>();
                context.put("URI_STRING", uriString);
                context.put("STATUS_OBJECT", resultStatusObject);
                context.put("STATUS_FILENAME", statusFileName);
                context.put("APPLICATION_ID", ConfigurationUtils.getApplicationKey(clientConfigObject));
                context.put("APPLICATION_SECRET", ConfigurationUtils.getApplicationSecret(clientConfigObject));
                context.put("HTTP_METHOD", cmd.getOptionValue("t"));
                context.put("ENDPOINT", cmd.getOptionValue("e"));
                context.put("SIGNATURE_TYPE", cmd.getOptionValue("l"));
                context.put("DATA_FILE_NAME", cmd.getOptionValue("d"));
                context.put("PASSWORD", cmd.getOptionValue("p"));

                VerifySignatureStep.execute(context);

            } else if (method.equals("unlock")) {

                Map<String, Object> context = new HashMap<>();
                context.put("URI_STRING", uriString);
                context.put("STATUS_OBJECT", resultStatusObject);
                context.put("STATUS_FILENAME", statusFileName);
                context.put("APPLICATION_ID", ConfigurationUtils.getApplicationKey(clientConfigObject));
                context.put("APPLICATION_SECRET", ConfigurationUtils.getApplicationSecret(clientConfigObject));
                context.put("SIGNATURE_TYPE", cmd.getOptionValue("l"));
                context.put("PASSWORD", cmd.getOptionValue("p"));

                VaultUnlockStep.execute(context);

            } else {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("java -jar powerauth-java-cmd.jar", options);
                return;
            }

        } catch (Exception e) {
            System.out.println("Unknown error - " + e.getLocalizedMessage());
            System.out.println();
            System.out.println("### Failed.");
            System.out.println();
        }

    }

}
