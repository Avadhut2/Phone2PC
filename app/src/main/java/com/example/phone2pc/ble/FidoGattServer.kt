package com.example.phone2pc.ble

import android.bluetooth.BluetoothGattServer
import android.content.Context

/**
 * FidoGattServer
 *
 * Manages the lifecycle of the Android BluetoothGattServer that exposes the
 * standard FIDO BLE Service (UUID 0xFFFD) and its required characteristics:
 *   - FIDO Control Point        (Write)
 *   - FIDO Status               (Notify)
 *   - FIDO Control Point Length (Read)
 *   - FIDO Service Revision     (Read)
 *
 * Security: This class is a dumb transport pipe only. It assembles raw byte
 * frames and forwards complete FIDO messages up to [BleFramer]. It never
 * inspects or acts on the payload content.
 *
 * Phase: 1 — BLE FIDO2 GATT Service
 */
class FidoGattServer(private val context: Context) {

    private var gattServer: BluetoothGattServer? = null

    /** Open the GATT server and register the FIDO service. */
    fun start() {
        // TODO(Phase 1): Initialize BluetoothManager, open GattServer,
        //                add FIDO service and characteristics.
    }

    /** Cleanly shut down the GATT server. */
    fun stop() {
        // TODO(Phase 1): Close gattServer and release resources.
        gattServer?.close()
        gattServer = null
    }
}
