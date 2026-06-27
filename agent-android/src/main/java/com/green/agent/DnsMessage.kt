package com.green.agent

object DnsMessage {
    data class Query(val domain: String, val qtype: Int, val questionEnd: Int)

    fun parseQuery(payload: ByteArray): Query? {
        if (payload.size < 12) return null
        var offset = 12
        val labels = mutableListOf<String>()
        while (offset < payload.size) {
            val length = payload[offset].toInt() and 0xff
            offset += 1
            if (length == 0) break
            if ((length and 0xc0) != 0 || offset + length > payload.size) return null
            labels += payload.copyOfRange(offset, offset + length).toString(Charsets.UTF_8)
            offset += length
        }
        if (offset + 4 > payload.size || labels.isEmpty()) return null
        val qtype = readU16(payload, offset)
        return Query(labels.joinToString("."), qtype, offset + 4)
    }

    fun blockedResponse(request: ByteArray, query: Query): ByteArray {
        val answerData = when (query.qtype) {
            1 -> byteArrayOf(0, 0, 0, 0)
            28 -> ByteArray(16)
            else -> ByteArray(0)
        }
        val hasAnswer = answerData.isNotEmpty()
        val answerSize = if (hasAnswer) 16 + answerData.size else 0
        val response = ByteArray(query.questionEnd + answerSize)
        response[0] = request[0]
        response[1] = request[1]
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[4] = 0.toByte()
        response[5] = 1.toByte()
        response[6] = 0.toByte()
        response[7] = (if (hasAnswer) 1 else 0).toByte()
        response[8] = 0.toByte()
        response[9] = 0.toByte()
        response[10] = 0.toByte()
        response[11] = 0.toByte()
        System.arraycopy(request, 12, response, 12, query.questionEnd - 12)
        if (hasAnswer) {
            var offset = query.questionEnd
            response[offset++] = 0xc0.toByte()
            response[offset++] = 0x0c.toByte()
            writeU16(response, offset, query.qtype)
            offset += 2
            writeU16(response, offset, 1)
            offset += 2
            writeU32(response, offset, 60)
            offset += 4
            writeU16(response, offset, answerData.size)
            offset += 2
            System.arraycopy(answerData, 0, response, offset, answerData.size)
        }
        return response
    }

    fun readU16(bytes: ByteArray, offset: Int): Int {
        return ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    }

    fun writeU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 1] = (value and 0xff).toByte()
    }

    private fun writeU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = ((value ushr 24) and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 16) and 0xff).toByte()
        bytes[offset + 2] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 3] = (value and 0xff).toByte()
    }
}
