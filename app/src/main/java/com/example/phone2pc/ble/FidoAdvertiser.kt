package com.example.phone2pc.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid

/**
 * FidoAdvertiser
 *
 * Manages Bluetooth Low Energy advertising so Windows can discover this device
 * as a FIDO2 security key. Advertises the standard FIDO service UUID (0xFFFD)
 * in the advertisement payload.
 *
 * Phase: 1 — BLE FIDO2 GATT Service
 */
class FidoAdvertiser(private val context: Context) {

    private var advertiser: BluetoothLeAdvertiser? = null

    companion object {
        /** Standard FIDO BLE service UUID as defined by the FIDO Alliance. */
        val FIDO_SERVICE_UUID: ParcelUuid = ParcelUuid.fromString("0000FFFD-0000-1000-8000-00805F9B34FB")
    }

    /** Begin advertising the FIDO service UUID over BLE. */
    fun startAdvertising() {
        // TODO(Phase 1): Configure AdvertiseSettings (low latency, connectable),
        //                build AdvertiseData with FIDO_SERVICE_UUID,
        //                and start advertising.
    }

    /** Stop BLE advertising. */
    fun stopAdvertising() {
        // TODO(Phase 1): Stop advertising and release resources.
        advertiser?.stopAdvertising(advertiseCallback)
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            // TODO(Phase 1): Log success (non-sensitive).
        }

        override fun onStartFailure(errorCode: Int) {
            // TODO(Phase 1): Log failure code and surface error to UI.
        }
    }
}
