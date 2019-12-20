package com.company.keystore.crypto;

import com.company.keystore.util.ByteUtil;
import com.kosprov.jargon2.api.Jargon2;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;

public class ArgonManage {
	public static enum Type {
		ARGON2d,
		ARGON2i,
		ARGON2id;

		Type(String value, String valueCapitalized) {
			this.value = value;
			this.valueCapitalized = valueCapitalized;
		}

		private String value = this.name().toLowerCase();
		private String valueCapitalized;

		Type() {
			this.valueCapitalized = Character.toUpperCase(this.value.charAt(0)) + this.value.substring(1);
		}

		public String getValue() {
			return this.value;
		}

		public String getValueCapitalized() {
			return this.valueCapitalized;
		}
	}

	private Jargon2.Type type;
	private String salt;
	public static final int memoryCost = 20480;
	public static final int timeCost = 4;
	public static final int parallelism = 2;
	public String version;

	public ArgonManage() {
	}


	public ArgonManage(Type type, String salt, String version) {
		this.type = Jargon2.Type.valueOf(type.name());
		this.salt = salt;
		this.version = version;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	// in is password input
	public byte[] hash(byte[] in){
		if(version.equals("2")){
			return Jargon2.jargon2Hasher().type(this.type).memoryCost(memoryCost)
					.timeCost(timeCost).parallelism(parallelism).salt(salt.getBytes(StandardCharsets.US_ASCII))
					.password(ByteUtil.merge(salt.getBytes(StandardCharsets.US_ASCII), in)).rawHash();
		}
		try{
			return Jargon2.jargon2Hasher().type(this.type).memoryCost(memoryCost)
					.timeCost(timeCost).parallelism(parallelism).salt(Hex.decodeHex(salt.toCharArray()))
					.password(
							(salt + new String(Hex.encodeHex(in))).getBytes()).rawHash();
		}catch (Exception e){throw new RuntimeException(e);}
	}

	public String kdf(){
		return this.type.name().toLowerCase();
	}

}
