package org.shiro.yara;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Yara {

	private static final Logger log = LoggerFactory.getLogger(Yara.class);
	private ProcessBuilder processBuilder = new ProcessBuilder();
	private List<File> rules = new ArrayList<File>();

	public Yara addRule(File rule) {
		log.info("add rule: " + rule.getName());
		rules.add(rule);
		return this;
	}

	public String scan(File file) {
		log.info("start scan file: " + file.getName());
		log.info("excute: yara " + rules.get(0).getAbsolutePath() + " " + file.getAbsolutePath());
		processBuilder.command("/bin/bash", "-c",
				"yara " + rules.get(0).getAbsolutePath() + " " + file.getAbsolutePath());
		return execute();
	}

	private String execute() {
		StringBuilder sb = new StringBuilder();
		try {
			Process process = processBuilder.start();
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				log.info(line);
				sb.append(line);
			}
			int exitCode = process.waitFor();
			log.info("Exited with error code : " + exitCode);
		} catch (IOException e) {
			log.error("failed to execute yara", e);
		} catch (InterruptedException e) {
			log.error("execute interrupted", e);
		}
		return sb.toString();
	}
}
