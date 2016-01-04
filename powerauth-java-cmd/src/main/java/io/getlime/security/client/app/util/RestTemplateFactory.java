package io.getlime.security.client.app.util;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class RestTemplateFactory {

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
