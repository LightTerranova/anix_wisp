package com.sinakamali.anix;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.Build;
import android.os.ParcelUuid;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

// BLE Insecure L2CAP transport for Anix
public class BleL2capTransport {

    // Some recovery for stalled transport
    // In most cases transport shouldn't fail
    private static final int CONNECT_MAX_ATTEMPTS = 3;
    private static final long CONNECT_RETRY_BACKOFF_MS = 500;
    private static final int ACCEPT_TIMEOUT_MS = 90000;

    // class so store a discovered Anix BLE server
    private static final class DiscoveredServer {
        final BluetoothDevice device;
        final int psm;
        DiscoveredServer(BluetoothDevice device, int psm) {
            this.device = device;
            this.psm = psm;
        }
    }

    private final BluetoothAdapter adapter;

    private BluetoothServerSocket serverSocket;
    private AdvertiseCallback advertiseCallback;
    private ScanCallback scanCallback;
    private UUID currentAdvertisedUuid;

    public BleL2capTransport(Context context) {
        BluetoothManager manager =
                (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        this.adapter = manager.getAdapter();
    }

    // opens an L2CAP listening channel, adv PSM and block until connected
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    public BluetoothSocket startServerAndAccept() throws IOException {
        serverSocket = adapter.listenUsingInsecureL2capChannel();
        int psm = serverSocket.getPsm();
        System.out.println("L2CAP listening on PSM " + psm);

        startAdvertising(psm);

        System.out.println("Waiting for client (timeout " + ACCEPT_TIMEOUT_MS + "ms)");
        // throws timeout instead of crash when a client does not connect
        BluetoothSocket socket = serverSocket.accept(ACCEPT_TIMEOUT_MS);
        System.out.println("Incoming L2CAP connection: " + socket.getRemoteDevice().getAddress());

        stopAdvertising();
        return socket;
    }

    // scans for L2CAP server broadcasts, opens a channel to a server and connects
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    public BluetoothSocket scanAndConnect(long timeoutMillis) throws Exception {
        IOException lastError = null;

        for (int attempt = 1; attempt <= CONNECT_MAX_ATTEMPTS; attempt++) {
            DiscoveredServer server = scanForServer(timeoutMillis); // throws if none found in time

            System.out.println("Connecting to " + server.device.getAddress() + " PSM " + server.psm
                    + "... (attempt " + attempt + "/" + CONNECT_MAX_ATTEMPTS + ")");

            BluetoothSocket socket = null;
            try {
                socket = server.device.createInsecureL2capChannel(server.psm);
                socket.connect();
                System.out.println("L2CAP socket connected to " + server.device.getAddress());
                return socket;
            } catch (IOException e) {
                // the stall bugs are both IOExceptions, handling them here
                lastError = e;
                System.out.println("Connect attempt " + attempt + " failed: " + e.getMessage());
                if (socket != null) {
                    try { socket.close(); } catch (IOException ignored) { }
                }
                if (attempt < CONNECT_MAX_ATTEMPTS) {
                    try {
                        Thread.sleep(CONNECT_RETRY_BACKOFF_MS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw ie;
                    }
                }
            }
        }

        throw (lastError != null)
                ? lastError
                : new IOException("Failed to connect after " + CONNECT_MAX_ATTEMPTS + " attempts");
    }

    // runs a BLE scan abd returns the first L2CAP server found
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    private DiscoveredServer scanForServer(long timeoutMillis) throws Exception {
        final byte[] irk = IrkStore.getIrk();

        final AtomicReference<BluetoothDevice> foundDevice = new AtomicReference<>(null);
        final AtomicReference<Integer> foundPsm = new AtomicReference<>(null);
        final CountDownLatch latch = new CountDownLatch(1);

        // Log UUIDs we already tried and rejected
        final Set<UUID> rejected = Collections.synchronizedSet(new HashSet<UUID>());

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();

        scanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                if (result == null || result.getScanRecord() == null) {
                    return;
                }
                Map<ParcelUuid, byte[]> serviceData = result.getScanRecord().getServiceData();
                if (serviceData == null || serviceData.isEmpty()) {
                    return;
                }

                for (Map.Entry<ParcelUuid, byte[]> entry : serviceData.entrySet()) {
                    byte[] value = entry.getValue();
                    if (value == null || value.length < 2) {
                        continue;
                    }
                    UUID candidate = entry.getKey().getUuid();
                    if (rejected.contains(candidate)) {
                        continue;
                    }
                    if (!ResolvableUuid.resolve(candidate, irk)) {
                        rejected.add(candidate);
                        continue;
                    }

                    int psm = ByteBuffer.wrap(value).getShort() & 0xFFFF;
                    // Take the first server
                    if (foundDevice.compareAndSet(null, result.getDevice())) {
                        foundPsm.set(psm);
                        System.out.println("Resolved L2CAP server: " + result.getDevice().getAddress()
                                + " PSM " + psm + " UUID " + candidate
                                + " (RSSI " + result.getRssi() + ")");
                        latch.countDown();
                    }
                    return;
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                System.out.println("Scan failed: error " + errorCode);
                latch.countDown();
            }
        };

        adapter.getBluetoothLeScanner().startScan(null, settings, scanCallback);
        System.out.println("Scanning for L2CAP servers...");

        boolean signalled = latch.await(timeoutMillis, TimeUnit.MILLISECONDS);
        stopScanning();

        BluetoothDevice device = foundDevice.get();
        Integer psm = foundPsm.get();
        if (!signalled || device == null || psm == null) {
            throw new IOException("No L2CAP server found within " + timeoutMillis + "ms");
        }
        return new DiscoveredServer(device, psm);
    }

    // BLE adv and scan helpers from Shroud L2CAP
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    private void startAdvertising(int psm) throws IOException {
        byte[] irk = IrkStore.getIrk();
        // new prand every time
        try {
            currentAdvertisedUuid = ResolvableUuid.generate(irk);
        } catch (Exception e) {
            throw new IOException("Failed to derive resolvable UUID", e);
        }
        ParcelUuid advUuid = new ParcelUuid(currentAdvertisedUuid);
        System.out.println("Advertising under resolvable UUID " + currentAdvertisedUuid);

        byte[] psmBytes = ByteBuffer.allocate(2).putShort((short) psm).array();

        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .build();

        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceData(advUuid, psmBytes)
                .build();

        advertiseCallback = new AdvertiseCallback() {
            @Override
            public void onStartSuccess(AdvertiseSettings settingsInEffect) {
                System.out.println("Advertising PSM " + psm);
            }

            @Override
            public void onStartFailure(int errorCode) {
                System.out.println("Advertise failed: error " + errorCode);
            }
        };
        adapter.getBluetoothLeAdvertiser().startAdvertising(settings, data, advertiseCallback);
    }

    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    private void stopAdvertising() {
        if (advertiseCallback != null) {
            adapter.getBluetoothLeAdvertiser().stopAdvertising(advertiseCallback);
            advertiseCallback = null;
        }
        currentAdvertisedUuid = null;
    }

    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    private void stopScanning() {
        if (scanCallback != null) {
            adapter.getBluetoothLeScanner().stopScan(scanCallback);
            scanCallback = null;
        }
    }

    // stop adv or scan and close connection
    @SuppressLint("MissingPermission")
    @RequiresApi(api = Build.VERSION_CODES.S)
    public void close() {
        stopAdvertising();
        stopScanning();
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            serverSocket = null;
        }
    }
}