package com.noovertime.demo.rsa;

public interface Constant {
	String ALGORITHM = "RSA";

	String GENERAL_RSA_PUBLIC_FILE = "general_rsa_public.pem";
	String GENERAL_RSA_PRIVATE_FILE = "general_rsa_private.pem";



	String ENCRYPT_RSA_KEY_ALGORITHM = "PBEWithSHA1AndDESede";
	char[] ENCRYPT_RSA_PASSWORD = "1234".toCharArray();
	String ENCRYPT_RSA_PUBLIC_FILE = "encrypt_rsa_public.pem";
	String ENCRYPT_RSA_PRIVATE_FILE = "encrypt_rsa_private.pem";
}
