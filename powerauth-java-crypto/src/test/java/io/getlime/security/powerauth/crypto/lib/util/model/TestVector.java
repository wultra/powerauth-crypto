/*
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.util.model;

import java.util.Map;

/**
 * Class representing a single test vector.
 */
public class TestVector {

    private final Map<String, String> input;
    private final Map<String, String> output;

    /**
     * Test vector constructor.
     * @param input Test vector input data.
     * @param output Test vector output data.
     */
    public TestVector(Map<String, String> input, Map<String, String> output) {
        this.input = input;
        this.output = output;
    }

    /**
     * Get test vector input data.
     * @return Test vector input data.
     */
    public Map<String, String> getInput() {
        return input;
    }

    /**
     * Get test vector output data.
     * @return Test vector output data.
     */
    public Map<String, String> getOutput() {
        return output;
    }

}