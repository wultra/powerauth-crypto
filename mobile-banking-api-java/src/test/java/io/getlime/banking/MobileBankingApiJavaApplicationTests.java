package io.getlime.banking;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.web.WebAppConfiguration;

import io.getlime.rest.api.MobileBankingApiJavaApplication;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MobileBankingApiJavaApplication.class)
@WebAppConfiguration
public class MobileBankingApiJavaApplicationTests {

	@Test
	public void contextLoads() {
	}

}
