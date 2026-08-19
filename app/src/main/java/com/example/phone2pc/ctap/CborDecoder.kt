package com.example.phone2pc.ctap


/**
 * CborDecoder
 *
 * Minimal CBOR decoder for parsing CTAP2 messages per RFC 7049.
 * Reads integer-keyed CBOR maps and extracts typed values.
 *
 * NOT a general-purpose CBOR library. Only handles CTAP2 structures.
 */
class CborDecoder(private val data: ByteArray) {

    private var pos = 0

    /** Read the next CBOR item and return it as a generic [Any?]. */
    fun read(): Any? {
        if (pos >= data.size) throw CborException("Unexpected end of data")

        val initial = data[pos++].toInt() and 0xFF
        val majorType = initial shr 5
        val additionalInfo = initial and 0x1F

        return when (majorType) {
            0 -> readUnsignedValue(additionalInfo)                         // Unsigned int
            1 -> -1L - readUnsignedValue(additionalInfo)                   // Negative int
            2 -> readBytes(readUnsignedValue(additionalInfo).toInt())      // Byte string
            3 -> String(readBytes(readUnsignedValue(additionalInfo).toInt()), Charsets.UTF_8) // Text string
            4 -> readArray(readUnsignedValue(additionalInfo).toInt())      // Array
            5 -> readMap(readUnsignedValue(additionalInfo).toInt())        // Map
            7 -> readSimple(additionalInfo)                                // Simple/float
            else -> throw CborException("Unsupported major type: $majorType")
        }
    }

    /** Convenience: decode the entire [data] as a CTAP2 integer-keyed map. */
    fun readIntKeyMap(): Map<Int, Any?> {
        val item = read()
        if (item !is Map<*, *>) throw CborException("Expected CBOR map, got ${item?.javaClass}")
        @Suppress("UNCHECKED_CAST")
        return (item as Map<Long, Any?>).mapKeys { it.key.toInt() }
    }

    private fun readUnsignedValue(additionalInfo: Int): Long = when {
        additionalInfo < 24 -> additionalInfo.toLong()
        additionalInfo == 24 -> readByte().toLong()
        additionalInfo == 25 -> readUInt16().toLong()
        additionalInfo == 26 -> readUInt32()
        additionalInfo == 27 -> readUInt64()
        else -> throw CborException("Invalid additional info: $additionalInfo")
    }

    private fun readBytes(length: Int): ByteArray {
        if (pos + length > data.size) throw CborException("Not enough data for byte string")
        val result = data.copyOfRange(pos, pos + length)
        pos += length
        return result
    }

    private fun readArray(size: Int): List<Any?> {
        val list = mutableListOf<Any?>()
        repeat(size) { list.add(read()) }
        return list
    }

    private fun readMap(size: Int): Map<Any?, Any?> {
        val map = linkedMapOf<Any?, Any?>()
        repeat(size) {
            val key = read()
            val value = read()
            map[key] = value
        }
        return map
    }

    private fun readSimple(additionalInfo: Int): Any? = when (additionalInfo) {
        20 -> false
        21 -> true
        22 -> null
        else -> throw CborException("Unsupported simple value: $additionalInfo")
    }

    private fun readByte(): Int {
        if (pos >= data.size) throw CborException("Unexpected end of data")
        return data[pos++].toInt() and 0xFF
    }

    private fun readUInt16(): Int {
        if (pos + 2 > data.size) throw CborException("Unexpected end of data")
        val result = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return result
    }

    private fun readUInt32(): Long {
        if (pos + 4 > data.size) throw CborException("Unexpected end of data")
        val result = ((data[pos].toLong() and 0xFF) shl 24) or
            ((data[pos + 1].toLong() and 0xFF) shl 16) or
            ((data[pos + 2].toLong() and 0xFF) shl 8) or
            (data[pos + 3].toLong() and 0xFF)
        pos += 4
        return result
    }

    private fun readUInt64(): Long {
        if (pos + 8 > data.size) throw CborException("Unexpected end of data")
        var result = 0L
        for (i in 0 until 8) {
            result = (result shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return result
    }
}

/** Exception for CBOR decoding errors. */
class CborException(message: String) : Exception(message)
