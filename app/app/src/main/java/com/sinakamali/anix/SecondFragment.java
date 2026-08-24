package com.sinakamali.anix;

import static android.content.Context.MODE_PRIVATE;
import static com.sinakamali.anix.anixCore.AnixCore.NOT_FOUND_ERROR;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.Fragment;
import androidx.navigation.fragment.NavHostFragment;

import com.sinakamali.anix.databinding.FragmentSecondBinding;
import com.sinakamali.anix.anixCore.KeyManager;
import com.sinakamali.anix.anixCore.AnixCore;
import com.sinakamali.anix.anixCore.AnixCoreMessage;
import com.sinakamali.anix.anixCore.PSU;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

public class SecondFragment extends Fragment {

    SharedPreferences sharedPref;
    private FragmentSecondBinding binding;
    private AnixCore internalAnixCore;

    // for anix proper
    private final BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    private final UUID MY_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    private static final String SAVED_MAC_ADDRESS_KEY = "saved_dst_mac";

    // How long the client scans for server before giving up
    private static final long SCAN_TIMEOUT_MS = 30000;

    private long goodputBytes;

    // Takes whatever is in the IRK box
    private void setIrk(View view) {
        try {
            IrkStore.setIrkFromHex(String.valueOf(binding.irkInput.getText()));
            Toast.makeText(getActivity(), "IRK set for this session", Toast.LENGTH_SHORT).show();
            System.out.println("IRK set (" + IrkStore.getIrk().length + " bytes)");
        } catch (IllegalArgumentException e) {
            Toast.makeText(getActivity(), e.getMessage(), Toast.LENGTH_LONG).show();
            System.out.println("IRK rejected: " + e.getMessage());
        }
    }

    private void doCryptoTest(View view) {
        StringBuilder messageText = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            messageText.append("*");
        }

        byte[] messageBytes = messageText.toString().getBytes();

        StringBuilder tempMessageText = new StringBuilder();
        for (int i = 0; i < 320; i++) {
            tempMessageText.append("*");
        }

        byte[] tempMessageBytes = tempMessageText.toString().getBytes();

        long start, end;
        String timeTook;

        Toast.makeText(getActivity(), "starting test...", Toast.LENGTH_SHORT).show();
        try {
//            AnixCoreMessage message = internalAnixCore.createMessage(messageText.toString().getBytes());

            System.out.println("len of message bytes: " + tempMessageBytes.length);
            byte[] tempEncryptedMessage = KeyManager.encryptMessage(internalAnixCore.keyManager.getCurrEncyptionPublicKey(), tempMessageBytes);
            System.out.println("len of encrypted message bytes: " + tempEncryptedMessage.length);

            // Test new create signature
//            Security.addProvider(new BouncyCastleProvider());
            byte[] privateKeyBytes = Base64.getUrlDecoder().decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
            byte[] publicKeyBytes = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);

            PrivateKeyInfo privKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(privateKeyBytes));
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privKeyInfo.getEncoded());
            // =========== Keys =========
            PrivateKey jcaPrivateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            org.bouncycastle.jcajce.interfaces.EdDSAPublicKey jcaPublicKey = ((EdDSAPrivateKey) jcaPrivateKey).getPublicKey();

            start = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                KeyManager.signMessageEdDSA(messageBytes, jcaPrivateKey);
                if (i % 5000 == 0) {
                    System.out.println((i / 5000) * 50 + "% done");
                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
                }
            }
            end = System.nanoTime();
            timeTook = String.valueOf((end - start) / 1000);
            Toast.makeText(getActivity(), "ending test sign messages EdDSA (us): " + timeTook, Toast.LENGTH_SHORT).show();
            System.out.println("ending test sign messages EdDSA (us): " + timeTook);


            // Test new verify signature
            byte[] signatureEdDSA = KeyManager.signMessageEdDSA(messageBytes, jcaPrivateKey);
            start = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                KeyManager.verifyMessageEdDSA(messageBytes, signatureEdDSA, jcaPublicKey);
                if (i % 5000 == 0) {
                    System.out.println((i / 5000) * 50 + "% done");
                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
                }
            }
            end = System.nanoTime();
            timeTook = String.valueOf((end - start) / 1000);
            Toast.makeText(getActivity(), "ending test verify signatures EdDSA (us): " + timeTook, Toast.LENGTH_SHORT).show();
            System.out.println("ending test verify signatures EdDSA (us): " + timeTook);


            // Test new create blinded signature
            BigInteger L = new BigInteger("2");
            L = L.pow(252);
            BigInteger b = new BigInteger("27742317777372353535851937790883648493");
            L = L.add(b);
            start = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                PrivateKey blindedPrivateKey = KeyManager.getBlindedPrivateKey(messageBytes, privateKeyBytes, publicKeyBytes);
                KeyManager.signMessageEdDSA(messageBytes, blindedPrivateKey);
                if (i % 5000 == 0) {
                    System.out.println((i / 5000) * 50 + "% done");
                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
                }
            }
            end = System.nanoTime();
            timeTook = String.valueOf((end - start) / 1000);
            Toast.makeText(getActivity(), "ending test blinded sign messages EdDSA (us): " + timeTook, Toast.LENGTH_SHORT).show();
            System.out.println("ending test blinded sign messages EdDSA (us): " + timeTook);


            // Test new verify blinded signature
            PrivateKey blindedPrivateKey = KeyManager.getBlindedPrivateKey(messageBytes, privateKeyBytes, publicKeyBytes);
            org.bouncycastle.jcajce.interfaces.EdDSAPublicKey blindedPublicKey = ((EdDSAPrivateKey) blindedPrivateKey).getPublicKey();
            byte[] signatureBlindedEdDSA = KeyManager.signMessageEdDSA(messageBytes, blindedPrivateKey);
            start = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                PublicKey taylorsBlindedPublicKey = KeyManager.getBlindedPublicKey(messageBytes, publicKeyBytes);
                KeyManager.verifyMessageEdDSA(messageBytes, signatureBlindedEdDSA, blindedPublicKey);
                if (i % 5000 == 0) {
                    System.out.println((i / 5000) * 50 + "% done");
                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
                }
            }
            end = System.nanoTime();
            timeTook = String.valueOf((end - start) / 1000);
            Toast.makeText(getActivity(), "ending test verify blinded signatures EdDSA (us): " + timeTook, Toast.LENGTH_SHORT).show();
            System.out.println("ending test verify blinded signatures EdDSA (us): " + timeTook);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void doCreateObjectTest(View view) {
        StringBuilder messageText = new StringBuilder();
        for (int i = 0; i < 255; i++) {
            messageText.append("*");
        }

        long start, end;
        String timeTook;

        try {
            // Message Creation
            PSU temPsu = internalAnixCore.keyManager.generateNewPSU();
            start = System.nanoTime();
            for (int i = 0; i < 10000; i++) {
                // New version
                AnixCoreMessage message = internalAnixCore.createMessage(messageText.toString().getBytes(), temPsu);
                if (i % 5000 == 0) {
                    System.out.println((i / 5000) * 50 + "% done");
                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
                }
            }
            end = System.nanoTime();
            timeTook = String.valueOf((end - start) / 1000);
            Toast.makeText(getActivity(), "ending test message creation (us): " + timeTook, Toast.LENGTH_SHORT).show();
            System.out.println("ending test message creation (us): " + timeTook);

            // Message Voting
//            AnixCoreMessage message = internalAnixCore.createMessage(messageText.toString().getBytes());
//            start = System.nanoTime();
//            for (int i = 0; i < 10000; i++) {
//                internalAnixCore.voteOnMessage(message, true);
//                if (i % 5000 == 0) {
//                    System.out.println((i / 5000) * 50 + "% done");
//                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
//                }
//            }
//            end = System.nanoTime();
//            timeTook = String.valueOf((end - start)/1000);
//            Toast.makeText(getActivity(), "ending test message voting (us): " + timeTook, Toast.LENGTH_SHORT).show();
//            System.out.println("ending test message voting (us): " + timeTook);

            // PSU Creation
//            AnixCore test_anixCore = new AnixCore();
//            start = System.nanoTime();
//            for (int i = 0; i < 10000; i++) {
//                test_anixCore.keyManager.generateNewPSU();
//                if (i % 5000 == 0) {
//                    System.out.println((i / 5000) * 50 + "% done");
//                    Toast.makeText(getActivity(), (i / 5000) * 50 + "% done", Toast.LENGTH_SHORT).show();
//                }
//            }
//            end = System.nanoTime();
//            timeTook = String.valueOf((end - start)/1000);
//            Toast.makeText(getActivity(), "ending test PSU generation (us): " + timeTook, Toast.LENGTH_SHORT).show();
//            System.out.println("ending test PSU generation (us): " + timeTook);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // builds message
    private byte[] buildTestBlob() throws Exception {
        final int MESSAGE_COUNT = 100;
        final int VOTE_COUNT = 10000;
        final int PAYLOAD_BYTES = 140;

        StringBuilder messageText = new StringBuilder();
        for (int i = 0; i < PAYLOAD_BYTES; i++) {
            messageText.append("a");
        }

        AnixCoreMessage message = internalAnixCore.createMessage(messageText.toString().getBytes());
        byte[] messageByteArray = message.dumpMessageToBytes();
        System.out.println(message.dumpMessageToString());
        System.out.println("message size is " + messageByteArray.length + "bytes");
        message = internalAnixCore.voteOnMessage(message, true);
        byte[] voteByteArray = message.dumpVotesToBytes();
        System.out.println(new String(voteByteArray, StandardCharsets.UTF_8));
        System.out.println("vote size is " + voteByteArray.length + "bytes");

        ByteArrayOutputStream internalByteStream = new ByteArrayOutputStream();
        for (int i = 0; i < MESSAGE_COUNT; i++) {
            internalByteStream.write(messageByteArray);
        }
        for (int i = 0; i < VOTE_COUNT; i++) {
            internalByteStream.write(voteByteArray);
        }

        int bytesSent = internalByteStream.size();

        goodputBytes = (long) MESSAGE_COUNT * PAYLOAD_BYTES + (long) VOTE_COUNT * voteByteArray.length;

        System.out.println("total size of data to send: " + bytesSent);
        System.out.println("goodput bytes (messages and votes): " + goodputBytes + "  other bytes: " + (bytesSent - goodputBytes) + " B");
        return internalByteStream.toByteArray();
    }

    // from original anix
    @SuppressLint("MissingPermission")
    private void sendMessagesOverRfcomm(View view) {
        runRfcomm(() -> {
            String dstMac = sharedPref.getString(SAVED_MAC_ADDRESS_KEY, "").trim();
            BluetoothServerSocket serverSocket = null;
            long bytesRead = 0;

            try {
                byte[] blob = buildTestBlob();
                long sentBytes = blob.length;

                BluetoothDevice device = bluetoothAdapter.getRemoteDevice(dstMac);
                if (device == null) {
                    System.out.println("device was null!");
                } else {
                    System.out.println("device was not null!");
                }

                BluetoothSocket socket = device.createInsecureRfcommSocketToServiceRecord(MY_UUID);
                long connectionStart = System.currentTimeMillis();
                long connectionEnd;
                socket.connect();
                System.out.println("connected!");
                OutputStream outputStream = socket.getOutputStream();
                if (outputStream == null) {
                    System.out.println("stream was null!");
                } else {
                    System.out.println("stream was not null!");
                }

                connectionEnd = System.currentTimeMillis();
                System.out.println("Establishing the connection 1 took: (ms)" + (connectionEnd - connectionStart));

                long start = System.currentTimeMillis();
                long sendStart = start;

                outputStream.write(blob);
                outputStream.flush();
                outputStream.close();

                long sendEnd = System.currentTimeMillis();

                // Receiving ===========

                serverSocket = bluetoothAdapter.listenUsingRfcommWithServiceRecord("Anix", MY_UUID);

                connectionStart = System.currentTimeMillis();
                connectionEnd = 0;

                System.out.println("listening for connection...");
                socket = serverSocket.accept(); // Blocking call, waits until connection is established
                InputStream inputStream = socket.getInputStream();
                byte[] buffer = new byte[1024];
                int bytes;

                long recvStart = 0;
                long recvEnd = 0;
                boolean first_impact = true;
                try {
                    while (true) {
                        bytes = inputStream.read(buffer); // blocks until there's something to read
                        if (bytes == -1) break; // sender closed
                        bytesRead += bytes;
                        if (first_impact) {
                            connectionEnd = System.currentTimeMillis();
                            recvStart = connectionEnd;
                            uiToast("GOT MESSAGE!!!");
                            System.out.println("Got message!");
                            first_impact = false;
                        }
                    }
                } catch (Exception e) {
                    System.out.println("out of receiving");
                }
                recvEnd = System.currentTimeMillis();

                long end = System.currentTimeMillis();
                System.out.println("Sending and receiving everything took: (ms)" + (end - start));
                System.out.println("Establishing the connection took: (ms)" + (connectionEnd - connectionStart));

                printThroughput("receive", goodputBytes, recvEnd - recvStart, sentBytes);
                printThroughput("send",    goodputBytes, sendEnd - sendStart, sentBytes);
                socket.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                if (serverSocket != null) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
    }

    @SuppressLint("MissingPermission")
    private void receiveMessagesOverRfcomm(View view) {
        runRfcomm(() -> {
            BluetoothServerSocket serverSocket = null;

            long start = 0, end;
            long bytesRead = 0;

            String dstMac = sharedPref.getString(SAVED_MAC_ADDRESS_KEY, "").trim();

            try {
                byte[] blob = buildTestBlob();
                long sentBytes = blob.length;

                serverSocket = bluetoothAdapter.listenUsingRfcommWithServiceRecord("Anix", MY_UUID);
                System.out.println("listening for connection...");
                BluetoothSocket socket = serverSocket.accept(); // Blocking call, waits until connection is established
                InputStream inputStream = socket.getInputStream();
                byte[] buffer = new byte[1024];
                int bytes;

                start = System.currentTimeMillis();
                long recvStart = 0;
                long recvEnd = 0;
                boolean first_impact = true;
                try {
                    while (true) {
                        bytes = inputStream.read(buffer); // blocks until there's something to read
                        if (bytes == -1) break;
                        bytesRead += bytes;
                        if (first_impact) {
                            recvStart = System.currentTimeMillis();
                            uiToast("GOT MESSAGE!!!");
                            System.out.println("Got message!");
                            first_impact = false;
                        }
                    }
                } catch (IOException e) {
                    System.out.println("out of receiving");
                }
                recvEnd = System.currentTimeMillis();
                socket.close();

                BluetoothDevice device = bluetoothAdapter.getRemoteDevice(dstMac);

                socket = device.createInsecureRfcommSocketToServiceRecord(MY_UUID);
                socket.connect();
                System.out.println("connected!");
                OutputStream outputStream = socket.getOutputStream();
                if (outputStream == null) {
                    System.out.println("stream was null!");
                } else {
                    System.out.println("stream was not null!");
                }

                long sendStart = System.currentTimeMillis();
                outputStream.write(blob);
                outputStream.flush();
                outputStream.close();
                long sendEnd = System.currentTimeMillis();

                end = System.currentTimeMillis();
                System.out.println("Sending and receiving everything took: (ms)" + (end - start));

                printThroughput("receive", goodputBytes, recvEnd - recvStart, sentBytes);
                printThroughput("send",    goodputBytes, sendEnd - sendStart, sentBytes);

                socket.close();

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                if (serverSocket != null) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });
    }

    // BLE L2CAP CoC
    @RequiresApi(api = Build.VERSION_CODES.S)
    private void sendMessagesOverBleL2cap(View view) {
        // ble scan and adv are on the main loop and transport calls block
        final Context ctx = requireContext().getApplicationContext();
        new Thread(() -> {

            long bytesRead = 0;

            BleL2capTransport clientTransport = new BleL2capTransport(ctx);
            BleL2capTransport serverTransport = new BleL2capTransport(ctx);

            try {
                byte[] blob = buildTestBlob();
                long sentBytes = blob.length;

                // scan for the adv PSM and open the channel
                long connectionStart = System.currentTimeMillis();
                long connectionEnd = 0;
                BluetoothSocket socket = clientTransport.scanAndConnect(SCAN_TIMEOUT_MS);
                System.out.println("connected!");
                OutputStream outputStream = socket.getOutputStream();
                if (outputStream == null) {
                    System.out.println("stream was null!");
                } else {
                    System.out.println("stream was not null!");
                }

                connectionEnd = System.currentTimeMillis();

                System.out.println("Establishing the connection 1 took: (ms)" + (connectionEnd - connectionStart));

                // send wait for ack before closing
                // no ack caused a bug where close would run before data transferred
                InputStream clientIn = socket.getInputStream();
                long start = System.currentTimeMillis();
                long sendStart = start;

                outputStream.write(blob);
                outputStream.flush();

                int ack = clientIn.read(); // blocks
                long sendEnd = System.currentTimeMillis();
                boolean sendAcked = (ack != -1);
                System.out.println(sendAcked ? "send acked by receiver" : "no ack");

                socket.close();

                // Receiving ===========


                // server side to listen, adv the PSM and accept reqs
                connectionStart = System.currentTimeMillis();
                connectionEnd = 0;

                System.out.println("listening for connection...");
                socket = serverTransport.startServerAndAccept(); // Blocking call, waits until connection is established
                InputStream inputStream = socket.getInputStream();
                OutputStream ackOut = socket.getOutputStream();
                byte[] buffer = new byte[1024];
                int bytes;

                long recvStart = 0;
                long recvEnd = 0;
                boolean first_impact = true;
                try {
                    // Read the expected size
                    while (bytesRead < sentBytes) {
                        bytes = inputStream.read(buffer); // blocks until data or EOF
                        if (bytes == -1) break; // send closed early
                        if (first_impact) {
                            connectionEnd = System.currentTimeMillis();
                            recvStart = connectionEnd; // first buff arrived
                            uiToast("GOT MESSAGE!!!");
                            System.out.println("Got message!");
                            first_impact = false;
                        }
                        bytesRead += bytes;
                    }
                    recvEnd = System.currentTimeMillis();

                    if (bytesRead >= sentBytes) {
                        // all received. send ACK
                        ackOut.write(0x06);
                        ackOut.flush();
                        System.out.println("full blob received (" + bytesRead + " bytes), ACK sent");
                        // Block until EOF
                        inputStream.read();
                    } else {
                        System.out.println("truncated receive: " + bytesRead + " of " + sentBytes);
                    }
                } catch (Exception e) {
                    System.out.println("out of receiving");
                    if (recvEnd == 0) recvEnd = System.currentTimeMillis();
                }

                long end = System.currentTimeMillis();
                System.out.println("Sending and receiving everything took: (ms)" + (end - start));
                System.out.println("Establishing the connection took: (ms)" + (connectionEnd - connectionStart));

                // Throughput calculations
                // receive is first inbound byte to last
                // send is write->ACK which includes the ACK transmissions
                printThroughput("receive", goodputBytes, recvEnd - recvStart, sentBytes);
                if (sendAcked) {
                    printThroughput("send", goodputBytes, sendEnd - sendStart, sentBytes);
                } else {
                    System.out.println("Throughput [send]: skipped (no ACK from receiver)");
                }

                socket.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                clientTransport.close();
                serverTransport.close();
            }
        }).start();
    }

    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    private void receiveMessagesOverBleL2cap(View view) {
        // treading to stop blocking UI
        final Context ctx = requireContext().getApplicationContext();
        new Thread(() -> {

            long start = 0, end;
            long bytesRead = 0;

            BleL2capTransport serverTransport = new BleL2capTransport(ctx);
            BleL2capTransport clientTransport = new BleL2capTransport(ctx);

            try {
                byte[] blob = buildTestBlob();
                long sentBytes = blob.length;

                // server side to listen, adv the PSM and accept reqs
                System.out.println("listening for connection...");
                BluetoothSocket socket = serverTransport.startServerAndAccept(); // Blocking call, waits until connection is established
                InputStream inputStream = socket.getInputStream();
                OutputStream ackOut = socket.getOutputStream();
                byte[] buffer = new byte[1024];
                int bytes;

                start = System.currentTimeMillis();
                long recvStart = 0;
                long recvEnd = 0;
                boolean first_impact = true;
                try {
                    // Read the expected size
                    while (bytesRead < sentBytes) {
                        bytes = inputStream.read(buffer); // blocks until data or EOF
                        if (bytes == -1) break; // send closed early
                        if (first_impact) {
                            recvStart = System.currentTimeMillis(); // first buff arrived
                            uiToast("GOT MESSAGE!!!");
                            System.out.println("Got message!");
                            first_impact = false;
                        }
                        bytesRead += bytes;
                    }
                    recvEnd = System.currentTimeMillis();

                    if (bytesRead >= sentBytes) {
                        // all received. send ACK
                        ackOut.write(0x06);
                        ackOut.flush();
                        System.out.println("full blob received (" + bytesRead + " bytes), ACK sent");
                        // Block until EOF
                        inputStream.read();
                    } else {
                        System.out.println("truncated receive: " + bytesRead + " of " + sentBytes);
                    }
                } catch (IOException e) {
                    System.out.println("out of receiving");
                    if (recvEnd == 0) recvEnd = System.currentTimeMillis();
                }
                socket.close();


                // scan for the adv PSM and open the channel
                socket = clientTransport.scanAndConnect(SCAN_TIMEOUT_MS);
                System.out.println("connected!");
                OutputStream outputStream = socket.getOutputStream();
                if (outputStream == null) {
                    System.out.println("stream was null!");
                } else {
                    System.out.println("stream was not null!");
                }

                // send wait for ack before closing
                // no ack caused a bug where close would run before data transferred
                InputStream clientIn = socket.getInputStream();
                long sendStart = System.currentTimeMillis();
                outputStream.write(blob);
                outputStream.flush();

                int ack = clientIn.read(); // blocks
                long sendEnd = System.currentTimeMillis();
                boolean sendAcked = (ack != -1);
                System.out.println(sendAcked ? "send ACKed by receiver" : "no ack");

                socket.close();


                end = System.currentTimeMillis();
                System.out.println("Sending and receiving everything took: (ms)" + (end - start));

                // Throughput calculations
                // receive is first inbound byte to last
                // send is write->ACK which includes the ACK transmissions
                printThroughput("receive", goodputBytes, recvEnd - recvStart, sentBytes);
                if (sendAcked) {
                    printThroughput("send", goodputBytes, sendEnd - sendStart, sentBytes);
                } else {
                    System.out.println("Throughput [send]: skipped (no ACK from receiver)");
                }

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                serverTransport.close();
                clientTransport.close();
            }
        }).start();
    }

    //helpers
    // run rfcomm used to check on which thread
    private void runRfcomm(Runnable body) {
        new Thread(body).start();
    }

    private void uiToast(String text) {
        if (getActivity() != null) {
            requireActivity().runOnUiThread(() ->
                    Toast.makeText(getActivity(), text, Toast.LENGTH_SHORT).show());
        }
    }

    // Prints throughput in kBps
    private void printThroughput(String direction, long bytes, long elapsedMs, long expectedBytes) {
        if (Objects.equals(direction, "receive")) {
            double kBps = (bytes / 1000.0) / (elapsedMs / 1000.0);
            System.out.println("Receiver Goodput: " + kBps + " kBps " + "(" + bytes + " bytes in " + elapsedMs + " ms" + ")");
            System.out.println("Total Sent Bytes: " + expectedBytes);
        }
    }

    @Override
    public View onCreateView(
            @NonNull LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState
    ) {

        binding = FragmentSecondBinding.inflate(inflater, container, false);

        sharedPref = requireActivity().getSharedPreferences("main", MODE_PRIVATE);

        return binding.getRoot();

    }

    private void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            return;
        }
        if (provider.getClass().equals(BouncyCastleProvider.class)) {
            return;
        }
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        setupBouncyCastle();

        binding.prevButton2.setOnClickListener(v ->
                NavHostFragment.findNavController(SecondFragment.this)
                        .navigate(R.id.action_SecondFragment_to_FirstFragment)
        );

        String keypair = sharedPref.getString(AnixCore.SAVED_KEYPAIR_KEY, NOT_FOUND_ERROR);
        try {
            internalAnixCore = new AnixCore(keypair);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Tell user IRK already set
        if (IrkStore.isSet()) {
            binding.irkInput.setHint("IRK already set this session");
        }

        binding.setIrkButton.setOnClickListener(this::setIrk);
        binding.cryptobutton.setOnClickListener(this::doCryptoTest);
        binding.componentbutton.setOnClickListener(this::doCreateObjectTest);

        // Anix transport
        binding.messagebutton.setOnClickListener(this::sendMessagesOverRfcomm);
        binding.receivebutton.setOnClickListener(this::receiveMessagesOverRfcomm);

        // BLE transport
        binding.blemessagebutton.setOnClickListener(this::sendMessagesOverBleL2cap);
        binding.blereceivebutton.setOnClickListener(this::receiveMessagesOverBleL2cap);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        System.out.println("hello world!!!");
    }
}