package io.getlime.security.service.util.model;

import java.util.ArrayList;
import java.util.List;

public class ServiceError {

	/**
	 * Unknown error occurred.
	 */
	public static final String ERR0000 = "ERR0000";

	/**
	 * No user ID was set.
	 */
	public static final String ERR0001 = "ERR0001";

	/**
	 * No application ID was set.
	 */
	public static final String ERR0002 = "ERR0002";

	/**
	 * No master server key pair configured in database.
	 */
	public static final String ERR0003 = "ERR0003";

	/**
	 * Master server key pair contains private key in incorrect format.
	 */
	public static final String ERR0004 = "ERR0004";

	/**
	 * Too many failed attempts to generate activation ID.
	 */
	public static final String ERR0005 = "ERR0005";

	/**
	 * Too many failed attempts to generate short activation ID.
	 */
	public static final String ERR0006 = "ERR0006";

	/**
	 * This activation is already expired.
	 */
	public static final String ERR0007 = "ERR0007";

	/**
	 * Only activations in OTP_USED state can be committed.
	 */
	public static final String ERR0008 = "ERR0008";

	/**
	 * Activation with given activation ID was not found.
	 */
	public static final String ERR0009 = "ERR0009";

	/**
	 * Key with invalid format was provided.
	 */
	public static final String ERR0010 = "ERR0010";

	/**
	 * Invalid input parameter format.
	 */
	public static final String ERR0011 = "ERR0011";

	/**
	 * Invalid Signature Provided.
	 */
	public static final String ERR0012 = "ERR0012";
	
	public static List<String> allCodes() {
		List<String> list = new ArrayList<>(13);
		list.add(ERR0000);
		list.add(ERR0001);
		list.add(ERR0002);
		list.add(ERR0003);
		list.add(ERR0004);
		list.add(ERR0005);
		list.add(ERR0006);
		list.add(ERR0007);
		list.add(ERR0008);
		list.add(ERR0009);
		list.add(ERR0010);
		list.add(ERR0011);
		list.add(ERR0012);
		return list;
	}

}
