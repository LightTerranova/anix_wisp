# Anix Wisp

Fork of the [Anix](https://cs.uwaterloo.ca/~s4kamali/paperfiles/kamali-sp25.pdf) paper. This repository holds an Android application with an experimental implementation of Anix over Bluetooth Low Energy (BLE) L2CAP Connection Oriented Channels (CoC) rather than Bluetooth Classic.

## Functions
1. Sends a predetermined payload via Blutooth Classic (Anix)
2. Sends a predetermined payload via Bluetooth Low Energy L2CAP CoC with static UUID and unencrypted PSM (Wisp Public Mode)
3. Sends a predetermined payload via Bluetooth Low Energy L2CAP CoC with Random Resolvable UUID and encrypted PSM (Wisp Private Mode)

## Running Instructions
1. Clone the repository using git clone
2. Open the project in Android Studio
3. Sync Gradle
4. Connect two Android devices via USB or WiFi Debugging
5. Run the application
6. Allow all permissions

## Sending via Bluetooth Classic (Anix)
1. Find the MAC Address of both devices by going to Settings -> About Phone -> Status Information -> Bluetooth Address
2. Input the MAC Address of the other device into the destination MAC address field
3. Click "Next"
4. Click "Receive" on one device
5. Click "Send" on the other device

## Sending via Bluetooth Low Energy Public Mode (Wisp)
1. Click "Next"
2. Click "Toggle Security"
5. Click "BLE Receive" on one device
6. Click "BLE Message Test" on the other device

## Sending via Bluetooth Low Energy Private Mode (Wisp)
1. Click "Next"
2. Enter an IRK manually or use the existing one
3. Click "Set IRK"
4. Click "BLE Receive" on one device
5. Click "BLE Message Test" on the other device

## Results
The logs of runs used for our throughput results can be found at the top level of this repository in a file called “All Experiments Final.txt”
