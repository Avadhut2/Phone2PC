package com.example.phone2pc.ble

import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.util.Log

/**
 * FidoAdvertiser
 *
 * Manages BLE advertising so Windows can discover this device as a FIDO2
 * security key. Advertises the standard FIDO service UUID (0xFFFD).
 *
 * Phase: 1 — BLE FIDO2 GATT Service
 */
class FidoAdvertiser(private val context: Context) {

    companion object {
        private const val TAG = "FidoAdvertiser"
    }

    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    /** Callback for advertising state changes. */
    var onStateChanged: ((advertising: Boolean, error: String?) -> Unit)? = null

    /** Begin advertising the FIDO service UUID over BLE. */
    fun startAdvertising() {
        if (isAdvertising) return

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? BluetoothManager ?: run {
            onStateChanged?.invoke(false, "BluetoothManager not available")
            return
        }

        advertiser = bluetoothManager.adapter?.bluetoothLeAdvertiser ?: run {
            onStateChanged?.invoke(false, "BLE advertising not supported on this device")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0) // Advertise indefinitely
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(FidoBleUuids.SERVICE_PARCEL)
            .setIncludeDeviceName(false) // Save advertisement space
            .build()

        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    /** Stop BLE advertising. */
    fun stopAdvertising() {
        if (!isAdvertising) return
        advertiser?.stopAdvertising(advertiseCallback)
        isAdvertising = false
        Log.i(TAG, "Advertising stopped")
        onStateChanged?.invoke(false, null)
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            isAdvertising = true
            Log.i(TAG, "FIDO BLE advertising started")
            onStateChanged?.invoke(true, null)
        }

        override fun onStartFailure(errorCode: Int) {
            isAdvertising = false
            val msg = when (errorCode) {
                ADVERTISE_FAILED_ALREADY_STARTED -> "Already advertising"
                ADVERTISE_FAILED_DATA_TOO_LARGE -> "Data too large"
                ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "BLE advertising not supported"
                ADVERTISE_FAILED_INTERNAL_ERROR -> "Internal error"
                ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "Too many advertisers"
                else -> "Unknown error: $errorCode"
            }
            Log.e(TAG, "Advertising failed: $msg")
            onStateChanged?.invoke(false, msg)
        }
    }
}
