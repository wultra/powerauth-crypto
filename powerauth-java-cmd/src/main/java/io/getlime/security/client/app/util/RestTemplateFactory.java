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
package io.getlime.security.client.app.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory class for the default {@link RestTemplate} instance.
 *
 * @author Petr Dvorak
 *
 */
public class RestTemplateFactory {

    /**
     * Return default RestTemplate skeleton.
     * @return Default RestTempalte skeleton.
     */
    public static RestTemplate defaultRestTemplate() {
        // Prepare converters
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter(mapper);
        List<HttpMessageConverter<?>> converters = new ArrayList<>();
        converters.add(converter);

        // Prepare the REST template
        RestTemplate template = new RestTemplate();
        template.setMessageConverters(converters);
        return template;
    }

}
