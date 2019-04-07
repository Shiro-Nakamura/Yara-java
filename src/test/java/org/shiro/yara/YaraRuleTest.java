package org.shiro.yara;

import static org.junit.Assert.assertThat;

import java.io.File;

import org.hamcrest.CoreMatchers;
import org.junit.Test;

public class YaraRuleTest {

	private static final File RULE = new File("src/main/resources/my_first_rule");
	private static final File TARGET = new File("src/main/resources/scan_dummy");

	@Test
	public void test_yara_rule() {
		Yara yara = new Yara();
		yara.addRule(RULE);
		String result = yara.scan(TARGET);
		assertThat(result, CoreMatchers.startsWith("dummy"));
	}

}
