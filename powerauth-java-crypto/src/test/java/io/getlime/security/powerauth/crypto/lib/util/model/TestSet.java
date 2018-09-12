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

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Class representing a test set saved to a JSON file with test vectors.
 */
public class TestSet {

    private final String fileName;
    private final String description;
    private final List<TestVector> data = new ArrayList<>();

    /**
     * Test set constructor.
     * @param fileName JSON file name.
     * @param description Test set description.
     */
    public TestSet(String fileName, String description) {
        this.fileName = fileName;
        this.description = description;
    }

    /**
     * JSON file name.
     * @return JSON file name.
     */
    @JsonIgnore
    public String getFileName() {
        return fileName;
    }

    /**
     * Get test set description.
     * @return Test set description.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Get test vectors.
     * @return Test vectors.
     */
    public List<TestVector> getData() {
        return data;
    }

    /**
     * Add test vectors.
     * @param input Input test vector data.
     * @param output Output test vector data.
     */
    public void addData(Map<String, String> input, Map<String, String> output) {
        TestVector testVector = new TestVector(input, output);
        data.add(testVector);
    }
}
