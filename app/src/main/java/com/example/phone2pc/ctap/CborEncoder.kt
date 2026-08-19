package com.example.phone2pc.ctap

import java.io.ByteArrayOutputStream

/**
 * CborEncoder
 *
 * Minimal CBOR encoder producing wire-format bytes per RFC 7049.
 * Supports exactly the CBOR types required by CTAP2:
 *   - Unsigned integers, negative integers
 *   - Byte strings, text strings
 *   - Maps (integer-keyed), arrays
 *   - Booleans
 *
 * NOT a general-purpose CBOR library. Only handles CTAP2 structures.
 */
class CborEncoder {

    private val out = ByteArrayOutputStream()

    fun toByteArray(): ByteArray = out.toByteArray()

    fun encodeUnsignedInt(value: Long): CborEncoder {
        writeTypeAndValue(MAJOR_UNSIGNED, value)
        return this
    }

    fun encodeNegativeInt(value: Long): CborEncoder {
        // CBOR negative int encodes (-1 - n), so value -1 → 0, value -2 → 1, etc.
        writeTypeAndValue(MAJOR_NEGATIVE, -1L - value)
        return this
    }

    fun encodeByteString(data: ByteArray): CborEncoder {
        writeTypeAndValue(MAJOR_BYTE_STRING, data.size.toLong())
        out.write(data)
        return this
    }

    fun encodeTextString(text: String): CborEncoder {
        val bytes = text.toByteArray(Charsets.UTF_8)
        writeTypeAndValue(MAJOR_TEXT_STRING, bytes.size.toLong())
        out.write(bytes)
        return this
    }

    fun encodeMapStart(size: Int): CborEncoder {
        writeTypeAndValue(MAJOR_MAP, size.toLong())
        return this
    }

    fun encodeArrayStart(size: Int): CborEncoder {
        writeTypeAndValue(MAJOR_ARRAY, size.toLong())
        return this
    }

    fun encodeBoolean(value: Boolean): CborEncoder {
        out.write(if (value) 0xF5.toInt() else 0xF4.toInt())
        return this
    }

    fun encodeNull(): CborEncoder {
        out.write(0xF6.toInt())
        return this
    }

    fun encodeMap(map: Map<*, *>): CborEncoder {
        encodeMapStart(map.size)
        for ((key, value) in map) {
            encodeAny(key)
            encodeAny(value)
        }
        return this
    }

    private fun encodeAny(value: Any?) {
        when (value) {
            is Long -> {
                if (value >= 0) encodeUnsignedInt(value)
                else encodeNegativeInt(value)
            }
            is Int -> {
                if (value >= 0) encodeUnsignedInt(value.toLong())
                else encodeNegativeInt(value.toLong())
            }
            is ByteArray -> encodeByteString(value)
            is String -> encodeTextString(value)
            is Boolean -> encodeBoolean(value)
            is Map<*, *> -> encodeMap(value)
            null -> encodeNull()
            else -> throw IllegalArgumentException("Unsupported CBOR type: ${value::class.java}")
        }
    }

    private fun writeTypeAndValue(majorType: Int, value: Long) {
        val major = majorType shl 5
        when {
            value < 24 -> out.write(major or value.toInt())
            value < 0x100 -> {
                out.write(major or 24)
                out.write(value.toInt())
            }
            value < 0x10000 -> {
                out.write(major or 25)
                out.write((value shr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            value < 0x100000000L -> {
                out.write(major or 26)
                out.write((value shr 24).toInt() and 0xFF)
                out.write((value shr 16).toInt() and 0xFF)
                out.write((value shr 8).toInt() and 0xFF)
                out.write(value.toInt() and 0xFF)
            }
            else -> {
                out.write(major or 27)
                for (i in 7 downTo 0) {
                    out.write((value shr (i * 8)).toInt() and 0xFF)
                }
            }
        }
    }

    companion object {
        const val MAJOR_UNSIGNED = 0
        const val MAJOR_NEGATIVE = 1
        const val MAJOR_BYTE_STRING = 2
        const val MAJOR_TEXT_STRING = 3
        const val MAJOR_ARRAY = 4
        const val MAJOR_MAP = 5
    }
}
