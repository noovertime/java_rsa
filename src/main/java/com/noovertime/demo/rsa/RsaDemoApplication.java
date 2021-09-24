package com.noovertime.demo.rsa;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RsaDemoApplication {
	public static void main(String[] args) throws Exception {
		final String plainText = "안녕하세요?";

		GeneralRsa generalRsa = new GeneralRsa();
		generalRsa.create();
		String enc1Txt = generalRsa.encrypt( plainText );
		String dec1Txt = generalRsa.decrypt( enc1Txt );
		log.debug("{}암호화 : {} {}복호화 : {}", System.lineSeparator(), enc1Txt, System.lineSeparator(), dec1Txt);

		EncryptRsa encryptRsa = new EncryptRsa();
		encryptRsa.create();
		String enc2Txt = encryptRsa.encrypt( plainText );
		String dec2Txt = encryptRsa.decrypt( enc2Txt );
		log.debug("{}암호화 : {} {}복호화 : {}", System.lineSeparator(), enc2Txt, System.lineSeparator(), dec2Txt);
	}
}
