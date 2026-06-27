package com.green.agent

object IpPacket {
    data class UdpDnsPacket(
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val dnsPayload: ByteArray
    )

    fun parseUdpDnsPacket(packet: ByteArray, length: Int): UdpDnsPacket? {
        if (length < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (version != 4 || ihl < 20 || length < ihl + 8) return null
        val protocol = packet[9].toInt() and 0xff
        if (protocol != 17) return null
        val sourceAddress = packet.copyOfRange(12, 16)
        val destinationAddress = packet.copyOfRange(16, 20)
        val sourcePort = readU16(packet, ihl)
        val destinationPort = readU16(packet, ihl + 2)
        if (destinationPort != 53) return null
        val udpLength = readU16(packet, ihl + 4)
        if (udpLength < 8 || ihl + udpLength > length) return null
        val dnsPayload = packet.copyOfRange(ihl + 8, ihl + udpLength)
        return UdpDnsPacket(sourceAddress, destinationAddress, sourcePort, destinationPort, dnsPayload)
    }

    fun buildUdpResponse(request: UdpDnsPacket, dnsPayload: ByteArray): ByteArray {
        val ipHeaderLength = 20
        val udpLength = 8 + dnsPayload.size
        val totalLength = ipHeaderLength + udpLength
        val packet = ByteArray(totalLength)
        packet[0] = 0x45.toByte()
        packet[1] = 0.toByte()
        writeU16(packet, 2, totalLength)
        writeU16(packet, 4, 0)
        writeU16(packet, 6, 0)
        packet[8] = 64.toByte()
        packet[9] = 17.toByte()
        System.arraycopy(request.destinationAddress, 0, packet, 12, 4)
        System.arraycopy(request.sourceAddress, 0, packet, 16, 4)
        writeU16(packet, 10, ipv4Checksum(packet, 0, ipHeaderLength))
        val udpOffset = ipHeaderLength
        writeU16(packet, udpOffset, request.destinationPort)
        writeU16(packet, udpOffset + 2, request.sourcePort)
        writeU16(packet, udpOffset + 4, udpLength)
        writeU16(packet, udpOffset + 6, 0)
        System.arraycopy(dnsPayload, 0, packet, udpOffset + 8, dnsPayload.size)
        return packet
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int {
        return ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    }

    private fun writeU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 1] = (value and 0xff).toByte()
    }

    private fun ipv4Checksum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        while (index < offset + length) {
            sum += ((bytes[index].toInt() and 0xff) shl 8) + (bytes[index + 1].toInt() and 0xff)
            while (sum > 0xffff) {
                sum = (sum and 0xffff) + (sum ushr 16)
            }
            index += 2
        }
        return sum.inv() and 0xffff
    }
}
