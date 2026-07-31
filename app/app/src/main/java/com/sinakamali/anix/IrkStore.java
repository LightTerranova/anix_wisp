package com.sinakamali.anix;

public final class IrkStore {

    // Volatile storage for Wisp IRK
    private static volatile byte[] irk = null;

    private IrkStore() { }
    public static void setIrkFromHex(String hex) {
        byte[] parsed = new byte[16];
        for (int i = 0; i < 16; i++) {
            parsed[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        irk = parsed;
    }

    public static byte[] getIrk() {
        return irk;
    }

    public static boolean isSet() {
        return irk != null;
    }

    public static void clear() {
        irk = null;
    }
}