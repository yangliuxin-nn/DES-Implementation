package com.assignment.file;

import java.io.*;
import java.util.Base64;

public class Des {
    // Binary encrypted data
    private int[] key_data = new int[64];
    // array of bytes after the encryption operation is completed
    private int[] encrypt_data = new int[64];
    private byte[] encrypt_code = new byte[8];
    // initialize the key into a two-dimensional binary array
    private int[][] key_array;
    // Cyclic shift operation function
    private int[] c0 = new int[28];
    private int[] d0 = new int[28];
    private int[] c1 = new int[28];
    private int[] d1 = new int[28];

    private int[] L0 = new int[32];
    private int[] R0 = new int[32];
    private int[] L1 = new int[32];
    private int[] R1 = new int[32];
    private int[] RE = new int[48];
    private int[][] S = new int[8][6];
    private int[] sBoxData = new int[8];
    private int[] sValue = new int[32];
    private int[] RP = new int[32];
    // CONSTANTS
    // Table of Position of 64 bits at initial level: Initial Permutation Table
    // 64-bit
    private final int[] INIT_REP_IP = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52,
            44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48,
            40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35,
            27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31,
            23, 15, 7};
    // Inverse Initial Permutation Table
    private final int[] INIT_INVER_REP_IP = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7,
            47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45,
            13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
            51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49,
            17, 57, 25};
    // // first key-hePermutation Table1, 56-bit
    private final int[] PC_1 = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50,
            42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44,
            36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
            61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
    //  second key-Permutation Table 48-bit
    private static final int[] PC_2 = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21,
            10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
            55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36,
            29, 32};
    //  Expansion D-box Table  48-bit
    private final int[] Ext_Per_E = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9,
            10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
            21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
    //  Straight Permutation Table
    //  P_Box  32-bit
    private final int[] P = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23,
            26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22,
            11, 4, 25};
    // S-box Table
    private final int[][][] S_Box = {
            {// S_Box[1]
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
            { // S_Box[2]
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
            { // S_Box[3]
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
            { // S_Box[4]
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
            { // S_Box[5]
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
            { // S_Box[6]
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
            { // S_Box[7]
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
            { // S_Box[8]
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
    };
    public final int[] LeftMove = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    // left Circular Shifting bits
    private final int LEFT_MOVE_COUNT = 16;
    // round number of encryption
    private final int ENCRY_COUNT = 16;
    // round number of decryption
    private final int DECIP_COUNT = 15;

    /**
     * des encryption
     *
     * @param en_data: data to be encrypted
     * @return the encrypted data after the encryption
     *
     */
    public byte[] encrypt_data(byte[] en_data, byte[] byte_key) {
        // convert into the standard data if expansion is needed
        byte[] format_key = dataToByte(byte_key);
        byte[] format_data = dataToByte(en_data);

        // length of the data
        int data_len = format_data.length;
        // construct a bye array to contain the encrypted data
        byte[] encrypted = new byte[data_len];

        // Encryption
        // get the encrypted data
        // flag 1 represents encryption
        encrypted = ecbModel(1, format_key, format_data, data_len, encrypted);

        return encrypted;
    }

    /**
     * des decryption
     *
     * @param de_data: data to be decrypted
     * @return the decrypted data after the decryption
     *
     */
    public byte[] decrypt_data(byte[] de_data, byte[] byte_key) {
        // convert into the standard data if expansion is needed
        byte[] format_key = dataToByte(byte_key);
        byte[] format_data = dataToByte(de_data);

        // length of the data
        int data_len = format_data.length;
        // construct a bye array to contain the encrypted data
        byte[] decrypted = new byte[data_len];

        // Decryption
        // the purpose if to remove the padding bits generated during encryption
        // flag 0 represents decryption
        decrypted = ecbModel(0, format_key, format_data, data_len, decrypted);

        byte[] decrypt_byte_array = null;
        int delete_len = decrypted[data_len - 8 - 1];
        if ((delete_len >= 1) && (delete_len <= 8)) {
        }
        else
            delete_len = 0;
        decrypt_byte_array = new byte[data_len - delete_len - 8];
        System.arraycopy(decrypted, 0, decrypt_byte_array, 0, data_len - delete_len - 8);

        return decrypt_byte_array;
    }

    // encrypt file
    public String encryptFile(String filepath, String key) {
        // convert the key into a byte array
        byte[] byte_key = key.getBytes();
        String f1 = System.getProperty("user.dir");
        // get the absolute address of the directory that will store the encrypted and decrypted file
        String address = f1 + "\\src\\com\\assignment\\file\\plainText";
        File file = new File(filepath);
        if (!file.isDirectory()) {
            byte[] fileByte = Util.getFileByte(filepath);
            // encryption
            byte[] result = encrypt_data(fileByte, byte_key);
            String encryptedFileName = "encrypt_" + file.getName();
            // convert the encrypted byte array into String of base64 type
            String base64 = Base64.getEncoder().encodeToString(result);
            // write the base64 String into the file
            Util.writeIntoFile(address + "\\" + encryptedFileName, base64);
            System.out.println(base64);
            // return the absolute address where the encrypted file is stored
            return address + "\\" + encryptedFileName;
        }
        return "Sorry that directory encryption is not supported.";
    }

    // decrypt file
    public String decryptFile(String filepath, String key) {
        // convert the key into a byte array
        byte[] byte_key = key.getBytes();
        String f1 = System.getProperty("user.dir");
        // get the absolute address of the directory that will store the encrypted and decrypted file
        String address = f1 + "\\src\\com\\assignment\\file\\plainText";
        // construct a file object
        File file = new File(filepath);
        // read the String base64 from file
        String encryptedBase64 = Util.readFromFile(file);
        System.out.println("encryptedBase64! " + encryptedBase64);
        // convert the base64 into byte array format
        byte[] result = Base64.getDecoder().decode(encryptedBase64);
        // decryption
        byte[] tem_result = decrypt_data(result, byte_key);
        String decryptedFileName = "decrypt_" + file.getName();
        Util.generateFile(tem_result, file.getParentFile().getAbsolutePath(), decryptedFileName);
        // return the absolute address where the decrypted file is stored
        return address + "\\" + decryptedFileName;
    }

    /**
     * Extend the secret key if needed
     *
     * @param data
     * @return
     */
    public byte[] dataToByte(byte[] data) {
        // 0~7 bytes expand to 8 bytes, 8~15 bytes expand to 16 bytes
        int len = data.length;
        int pad_len = 8 - (len % 8);
        int new_len = len + pad_len;
        byte[] new_data = new byte[new_len];
        // copy the complete data to new_data
        System.arraycopy(data, 0, new_data, 0, len);
        // Expansion
        for (int i = len; i < new_len; i++)
            new_data[i] = (byte) pad_len;
        return new_data;
    }

    /**
     * Encryption/decryption of plaintext using ECB mode
     *
     * @param flag 1 represents encryption and 0 represents decryption
     * @param format_key
     * @param format_data
     * @param data_len
     * @param result_data
     */
    public byte[] ecbModel(int flag, byte[] format_key, byte[] format_data, int data_len, byte[] result_data) {
        // Use the ECB mode ECB
        // encrypt 8 bytes each time
        int number = data_len / 8;
        byte[] tmp_key = new byte[8];
        byte[] tmp_data = new byte[8];
        // Take the first eight bytes of the secret key after the formatting session
        System.arraycopy(format_key, 0, tmp_key, 0, 8);
        for (int i = 0; i < number; i++) {
            // Take 8 bytes of the formatted data at a time
            System.arraycopy(format_data, i * 8, tmp_data, 0, 8);
            byte[] tmp_result = blockOperation(tmp_key, tmp_data, flag);
            System.arraycopy(tmp_result, 0, result_data, i * 8, 8);
        }
        return result_data;
    }

    /**
     * Encrypt and decrypt every 8 bytes
     *
     * @param des_key  key used for encryption and decryption
     * @param des_data data
     * @param flag     1 represents encryption，0 represents decryption
     * @return byte array
     */
    public byte[] blockOperation(byte[] des_key, byte[] des_data, int flag) {
        // Initialize the key to a two-dimensional key array
        key_data = Util.readDataToBinaryIntArray(des_key);
        // Convert encrypted data byte arrays to binary byte arrays
        encrypt_data = Util.readDataToBinaryIntArray(des_data);
        key_array = new int[16][48];
        // Generate 16 48-bit sub-secret keys
        key_array = keyGeneration(key_data, key_array);
        encrypt_code = Encrypt(encrypt_data, flag, key_array);
        return encrypt_code;
    }

    // The initial key is written as Y0,
    // which consists of 64 bits of 01 sequence, but 8 of them are used for parity check,
    // so only 56 bits are actually used for encryption, which is written as K0
    private int[] K0 = new int[56];

    /**
     * Generate 16 sub-secret keys
     *
     * @param key      Initial 64-bit binary secret key
     * @param key_array Store the sub-secret key for each round
     */
    public int[][] keyGeneration(int[] key, int[][] key_array) {
        for (int i = 0; i < 56; i++) {
            // The key undergoes a PC-1 transformation.
            // If the i-th bit of the replacement table PC_1 is n, put the n-th bit of the data table key (key[n-1]) into the i-th bit of this K0 table
            K0[i] = key[PC_1[i] - 1];
        }
        for (int i = 0; i < LEFT_MOVE_COUNT; i++) {
            // Ci,Di cycle left shift to get Ci+1,Di+1, Ci+1Di+1 combined to do PC_2 replacement
            leftBitMove(K0, LeftMove[i]);
            for (int j = 0; j < 48; j++) {
                // Generate subkey key_array[i][j]
                key_array[i][j] = K0[PC_2[j] - 1];
            }
        }
        return key_array;
    }

    /**
     * Cyclic left shift
     *
     * @param k      56 binary bits generated by permutation function PC-1
     * @param offset Number of bits shifted left
     */
    public void leftBitMove(int[] k, int offset) {
        for (int i = 0; i < 28; i++) {
            c0[i] = k[i];
            d0[i] = k[i + 28];
        }
        if (offset == 1) {
            // Loop left by one
            for (int i = 0; i < 27; i++) {
                c1[i] = c0[i + 1];
                d1[i] = d0[i + 1];
            }
            c1[27] = c0[0];
            d1[27] = d0[0];
        } else if (offset == 2) {
            // Loop left by two
            for (int i = 0; i < 26; i++) {
                c1[i] = c0[i + 2];
                d1[i] = d0[i + 2];
            }
            c1[26] = c0[0];
            d1[26] = d0[0];
            c1[27] = c0[1];
            d1[27] = d0[1];
        }
        for (int i = 0; i < 28; i++) {
            k[i] = c1[i];
            k[i + 28] = d1[i];
        }
    }

    /**
     * perform the encryption or decryption
     *
     * @param encrypt_data  64-bit plaintext
     * @param flag  1 represents encryption and 0 represents decryption
     * @param key_array  sub-keys for 16 loops
     * @return
     */
    private byte[] result = new byte[8];
    private int[] MIP_1 = new int[64];
    private int[] M = new int[64];

    private byte[] Encrypt(int[] encrypt_data, int flag, int[][] key_array) {
        // Initial permutation of plaintext by initial permutation function
        for (int i = 0; i < 64; i++) {
            // Plaintext IP conversion
            M[i] = encrypt_data[INIT_REP_IP[i] - 1];
        }
        // encryption
        if (flag == 1) {
            for (int i = 0; i < ENCRY_COUNT; i++) {
                M = loop_function(M, i, flag, key_array);
            }
        }
        // decryption
        else if (flag == 0) {
            for (int i = DECIP_COUNT; i >= 0; i--) {
                M = loop_function(M, i, flag, key_array);
            }
        }
        // Perform the inverse IP_1 operation
        for (int i = 0; i < 64; i++) {
            MIP_1[i] = M[INIT_INVER_REP_IP[i] - 1];
        }
        // Return result data: encrypted data if flag is 1 or decrypted data if flag is 0
        result = Util.binaryIntArrayToInt(MIP_1);
        return result;
    }

    /**
     * 16 rounds of loop iteration
     *
     * @param M        plainText
     * @param round    number of loops
     * @param flag     1 represents encryption and 0 represents decryption
     * @param key_array Sub-secret key for each round
     */
    private int[] loop_function(int[] M, int round, int flag, int[][] key_array) {
        for (int i = 0; i < 32; i++) {
            // Initialization of the left side of the plaintext
            L0[i] = M[i];
            // Initialization of the right side of the plaintext
            R0[i] = M[i + 32];
        }
        // R0 goes through the expansion substitution table E, which changes from 32-bit to 48-bit RE,
        // and then encrypted by the sub-secret key Ki
        for (int i = 0; i < 48; i++) {
            RE[i] = R0[Ext_Per_E[i] - 1];
            // Sub-secret key Ki encryption, and KeyArray[times][i] by bit for not rounding addition (iso-or operation)
            RE[i] = RE[i] + key_array[round][i];
            if (RE[i] == 2) {
                RE[i] = 0;
            }
        }
        // RE is compressed by S-box to 32-bit sValue
        for (int i = 0; i < 8; i++) {
            // 48 is divided into 8 groups, 6 in each group
            System.arraycopy(RE, (i * 6), S[i], 0, 6);
            // The following goes through the S-box to get a decimal number
            sBoxData[i] = S_Box[i][(S[i][0] << 1) + S[i][5]][(S[i][1] << 3) + (S[i][2] << 2) + (S[i][3] << 1) + S[i][4]];
            // The decimal number obtained in the S-box becomes 4-bit binary
            for (int j = 0; j < 4; j++) {
                sValue[((i * 4) + 3) - j] = sBoxData[i] % 2;
                sBoxData[i] = sBoxData[i] / 2;
            }
        }
        // P permutation
        M = P_permutation(M, round, flag);
        return M;
    }

    private int[] P_permutation(int[] M, int round, int flag){
        // sValue is transformed by P into 32-bit RP
        for (int i = 0; i < 32; i++) {
            // P transformation
            RP[i] = sValue[P[i] - 1];
            // Move right to left
            L1[i] = R0[i];
            // The sum of L0 and RP is added bitwise (heterogeneous or operation) to obtain R1
            R1[i] = L0[i] + RP[i];
            if (R1[i] == 2) {
                R1[i] = 0;
            }
            // Re-synthesize M and return the array M
            // In the last transformation, the left and right are not swapped. Here two transformations are used to achieve invariance
            if (((flag == 0) && (round == 0)) || ((flag == 1) && (round == 15))) {
                M[i] = R1[i];
                M[i + 32] = L1[i];
            } else {
                M[i] = L1[i];
                M[i + 32] = R1[i];
            }
        }
        return M;
    }


}

