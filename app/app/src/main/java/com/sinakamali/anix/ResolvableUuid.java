package com.sinakamali.anix;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Resolvable private UUID based on BLE IRK
// Layout prand 3 bytes || truncated ah(IRK, prand) 13 bytes
public final class ResolvableUuid {
    private static final int PRAND_BYTES = 3;
    private static final int HASH_BYTES = 13;
    private static final SecureRandom RNG = new SecureRandom();

    private ResolvableUuid() { }
    // gen prand and UUID
    public static UUID generate(byte[] irk) throws Exception {
        byte[] prand = new byte[PRAND_BYTES];
        RNG.nextBytes(prand);

        byte[] uuidBytes = new byte[16];
        System.arraycopy(prand, 0, uuidBytes, 0, PRAND_BYTES);
        System.arraycopy(ah(irk, prand), 0, uuidBytes, PRAND_BYTES, HASH_BYTES);
        return fromBytes(uuidBytes);
    }

    // True if UUID was generated with our IRK
    public static boolean resolve(UUID candidate, byte[] irk) {
        try {
            byte[] bytes = toBytes(candidate);
            byte[] prand = Arrays.copyOfRange(bytes, 0, PRAND_BYTES);
            byte[] hash = Arrays.copyOfRange(bytes, PRAND_BYTES, 16);
            return MessageDigest.isEqual(ah(irk, prand), hash);
        } catch (Exception e) {
            return false;
        }
    }

    // ah(irk, prand) = AES(irk, padding || prand)
    // I truncate to 108 bits because we have the space in the uuid
    private static byte[] ah(byte[] irk, byte[] prand) throws Exception {
        byte[] block = new byte[16];
        System.arraycopy(prand, 0, block, 16 - prand.length, prand.length);

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(irk, "AES"));
        byte[] out = cipher.doFinal(block);

        return Arrays.copyOfRange(out, 16 - HASH_BYTES, 16);
    }

    private static byte[] toBytes(UUID uuid) {
        return ByteBuffer.allocate(16)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    private static UUID fromBytes(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }
}