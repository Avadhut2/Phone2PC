package com.example.phone2pc.ble

import android.os.ParcelUuid
import java.util.UUID

/**
 * FidoBleUuids
 *
 * Standard FIDO BLE UUIDs as defined by the FIDO Alliance CTAP2 specification.
 * All UUIDs follow the Bluetooth Base UUID format: 0000XXXX-0000-1000-8000-00805F9B34FB
 */
object FidoBleUuids {

    /** FIDO BLE Service UUID (0xFFFD). */
    val SERVICE: UUID = UUID.fromString("0000FFFD-0000-1000-8000-00805F9B34FB")
    val SERVICE_PARCEL: ParcelUuid = ParcelUuid(SERVICE)

    /** fidoControlPoint — Write. The client writes CTAP2 commands here. */
    val CONTROL_POINT: UUID = UUID.fromString("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB")

    /** fidoStatus — Notify. The authenticator sends responses here. */
    val STATUS: UUID = UUID.fromString("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB")

    /** fidoControlPointLength — Read. Returns the max fragment size the authenticator accepts. */
    val CONTROL_POINT_LENGTH: UUID = UUID.fromString("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB")

    /** fidoServiceRevisionBitfield — Read/Write. Protocol version bitfield. */
    val SERVICE_REVISION_BITFIELD: UUID = UUID.fromString("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB")

    /** Client Characteristic Configuration Descriptor — required for notifications. */
    val CCC_DESCRIPTOR: UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")
}
