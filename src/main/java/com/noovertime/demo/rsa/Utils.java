package com.noovertime.demo.rsa;

import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

@Slf4j
public class Utils {
	/**
	 * byte 배열을 BASE64 인코딩 하여 파일로 저장
	 * @param type 머리, 꼬리에 들어갈 키 정보
	 * @param path 파일, 존재하면 삭제 후 재생성
	 * @param bytes 대상 바이트
	 * @throws Exception 처리 중 예외
	 */
	public static void saveBase64Encode(String type, Path path, byte[] bytes) throws Exception {
		// 파일이 이미 존재하면 삭제
		if( path.toFile().exists()) {
			path.toFile().delete();
		}

		try ( FileOutputStream fOut = new FileOutputStream( path.toFile()) ) {
			if( type != null) {
				fOut.write(("-----BEGIN " + type + " KEY-----").getBytes(StandardCharsets.UTF_8));
				fOut.write( System.lineSeparator().getBytes(StandardCharsets.UTF_8));
			}


			fOut.write( Base64.getEncoder().encode( bytes ) );


			if( type != null) {
				fOut.write( System.lineSeparator().getBytes(StandardCharsets.UTF_8));
				fOut.write(("-----END " + type + " KEY-----").getBytes(StandardCharsets.UTF_8));
			}
		}
	}

	/**
	 * 키 파일의 머리/꼬리 떼기
	 * @param file 대상 파일
	 * @return 뗀 결과
	 * @throws Exception 처리 중 예외
	 */
	public static byte[] loadBody(File file) throws Exception {
		byte[] allBytes = Files.readAllBytes( file.toPath());
		String allStr = new String( allBytes );

		allStr = allStr.replaceAll("-----(BEGIN|END) .* KEY-----", "")
				.replaceAll(System.lineSeparator(), "");

		return allStr.getBytes(StandardCharsets.UTF_8);
	}


	public static void log(Key key) throws Exception {
		StringBuilder builder = new StringBuilder( System.lineSeparator());

		if( key instanceof PublicKey) {
			builder.append("* PUBLIC * ").append( System.lineSeparator());
		}
		else {
			builder.append("* PRIVATE * ").append( System.lineSeparator());
		}

		builder.append("- algorithm : ").append( key.getAlgorithm() ).append( System.lineSeparator());
		builder.append("- format : ").append( key.getFormat() ).append( System.lineSeparator());

		if( key instanceof RSAPublicKey) {
			RSAPublicKey rsaKey = (RSAPublicKey) key;
			builder.append("- module : ").append( rsaKey.getModulus() ).append( System.lineSeparator());
			builder.append("- publicExponent : ").append( rsaKey.getPublicExponent() ).append( System.lineSeparator());
			AlgorithmParameterSpec paramSpec = rsaKey.getParams();
			if( paramSpec != null) {
				builder.append("- algorithm param : ").append( paramSpec ).append( System.lineSeparator());
			}
		}
		else if( key instanceof RSAPrivateKey) {
			RSAPrivateKey rsaKey = (RSAPrivateKey) key;
			builder.append("- module : ").append( rsaKey.getModulus() ).append( System.lineSeparator());
			builder.append("- privateExponent : ").append( rsaKey.getPrivateExponent()).append( System.lineSeparator());
		}

		log.debug("{}", builder);
	}
}
