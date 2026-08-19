package com.example.phone2pc.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.content.Context
import android.util.Log

/**
 * FidoGattServer
 *
 * Manages the BluetoothGattServer exposing the FIDO BLE Service (0xFFFD)
 * with characteristics required by the CTAP2 BLE specification.
 *
 * This class is a transport pipe only — it receives raw BLE writes,
 * passes them through [BleFramer] for reassembly, and forwards complete
 * FIDO messages to [onMessageReceived]. It never inspects payload content.
 *
 * Phase: 1 — BLE FIDO2 GATT Service
 */
class FidoGattServer(private val context: Context) {

    companion object {
        private const val TAG = "FidoGattServer"
        private const val MAX_FRAGMENT_SIZE = 512  // Max bytes we accept per write
    }

    private var gattServer: BluetoothGattServer? = null
    private var connectedDevice: BluetoothDevice? = null
    private var statusCharacteristic: BluetoothGattCharacteristic? = null
    private val framer = BleFramer()

    /**
     * Callback invoked when a complete FIDO message has been reassembled.
     * Set this before calling [start]. The ByteArray is CMD + full payload.
     */
    var onMessageReceived: ((ByteArray) -> Unit)? = null

    /** Callback invoked when a device connects or disconnects. */
    var onConnectionStateChanged: ((connected: Boolean) -> Unit)? = null

    /** Open the GATT server and register the FIDO service. */
    fun start() {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? BluetoothManager ?: run {
            Log.e(TAG, "BluetoothManager not available")
            return
        }

        gattServer = bluetoothManager.openGattServer(context, gattCallback) ?: run {
            Log.e(TAG, "Failed to open GATT server")
            return
        }

        val service = buildFidoService()
        gattServer?.addService(service)
        Log.i(TAG, "FIDO GATT server started")
    }

    /** Send a FIDO response back to the connected device via notifications. */
    fun sendResponse(data: ByteArray) {
        val server = gattServer ?: return
        val device = connectedDevice ?: return
        val characteristic = statusCharacteristic ?: return

        val mtu = 20 // Conservative default; updated on MTU negotiation
        val frames = framer.fragment(data[0], data.copyOfRange(1, data.size), mtu)

        for (frame in frames) {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                server.notifyCharacteristicChanged(device, characteristic, false, frame)
            } else {
                @Suppress("DEPRECATION")
                characteristic.value = frame
                @Suppress("DEPRECATION")
                server.notifyCharacteristicChanged(device, characteristic, false)
            }
        }
    }

    /** Cleanly shut down the GATT server. */
    fun stop() {
        connectedDevice = null
        framer.reset()
        gattServer?.close()
        gattServer = null
        Log.i(TAG, "FIDO GATT server stopped")
    }

    private fun buildFidoService(): BluetoothGattService {
        val service = BluetoothGattService(
            FidoBleUuids.SERVICE,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // fidoControlPoint — Write (client sends CTAP2 commands here)
        val controlPoint = BluetoothGattCharacteristic(
            FidoBleUuids.CONTROL_POINT,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(controlPoint)

        // fidoStatus — Notify (authenticator sends responses here)
        val status = BluetoothGattCharacteristic(
            FidoBleUuids.STATUS,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0 // No direct read/write permission; data flows via notifications
        )
        val cccDescriptor = BluetoothGattDescriptor(
            FidoBleUuids.CCC_DESCRIPTOR,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        status.addDescriptor(cccDescriptor)
        service.addCharacteristic(status)
        statusCharacteristic = status

        // fidoControlPointLength — Read (tells client our max fragment size)
        val controlPointLength = BluetoothGattCharacteristic(
            FidoBleUuids.CONTROL_POINT_LENGTH,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        service.addCharacteristic(controlPointLength)

        // fidoServiceRevisionBitfield — Read/Write (protocol version)
        val serviceRevision = BluetoothGattCharacteristic(
            FidoBleUuids.SERVICE_REVISION_BITFIELD,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(serviceRevision)

        return service
    }

    private val gattCallback = object : BluetoothGattServerCallback() {

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                connectedDevice = device
                framer.reset()
                Log.i(TAG, "Device connected")
                onConnectionStateChanged?.invoke(true)
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                connectedDevice = null
                framer.reset()
                Log.i(TAG, "Device disconnected")
                onConnectionStateChanged?.invoke(false)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (characteristic.uuid == FidoBleUuids.CONTROL_POINT) {
                // Send GATT success response first
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
                // Feed into framer for reassembly
                try {
                    val completeMessage = framer.accumulate(value)
                    if (completeMessage != null) {
                        onMessageReceived?.invoke(completeMessage)
                    }
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "Malformed BLE frame rejected: ${e.message}")
                    framer.reset()
                }
            } else if (characteristic.uuid == FidoBleUuids.SERVICE_REVISION_BITFIELD) {
                // Client writing supported protocol version
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            } else {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, 0, null)
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            when (characteristic.uuid) {
                FidoBleUuids.CONTROL_POINT_LENGTH -> {
                    // Return max fragment size as 2-byte big-endian uint16
                    val value = byteArrayOf(
                        (MAX_FRAGMENT_SIZE shr 8 and 0xFF).toByte(),
                        (MAX_FRAGMENT_SIZE and 0xFF).toByte()
                    )
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
                FidoBleUuids.SERVICE_REVISION_BITFIELD -> {
                    // Bit 5 (0x20) = FIDO2 / CTAP2 supported
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, byteArrayOf(0x20))
                }
                else -> {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, 0, null)
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            // Client enabling/disabling notifications on fidoStatus
            if (descriptor.uuid == FidoBleUuids.CCC_DESCRIPTOR) {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            } else {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, 0, null)
                }
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            if (descriptor.uuid == FidoBleUuids.CCC_DESCRIPTOR) {
                gattServer?.sendResponse(
                    device, requestId, BluetoothGatt.GATT_SUCCESS, 0,
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                )
            }
        }
    }
}
