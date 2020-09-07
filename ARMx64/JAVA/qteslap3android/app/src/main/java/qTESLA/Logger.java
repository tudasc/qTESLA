package qTESLA;

import java.util.ArrayList;;

public class Logger {
    public static ArrayList<String> messages = new ArrayList<String> (100);
    public static int counter = 0;
    public static int no_of_threads = 1;
    public static boolean test_qtesla = true;
    public static boolean test_rsa = true;
    public static boolean test_ecdsa = true;
    public static int rsa_bitlen = 1024;
    public static byte[] seed;


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
