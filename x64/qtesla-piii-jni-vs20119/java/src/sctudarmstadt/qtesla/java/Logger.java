package sctudarmstadt.qtesla.java;

import java.util.ArrayList;;

public class Logger {
	public static ArrayList<String> messages = new ArrayList<String> (100);
	public static int counter = 0;
	public static byte[] seed;
	public static int no_of_threads = 3;
	public static boolean do_qtesla = false;
	public static boolean do_ecdsa = false;
	public static boolean do_rsa = false;
	
	public static void addMessage(String s) {
		messages.add(s);
		counter++;
		return;
	}
	
	public static String popMessage() {
		return messages.get(counter-1);
	}
	
	public static boolean entriesLeft() {
		if(counter > 0)
			return true;
		else
			return false;
	}
}
