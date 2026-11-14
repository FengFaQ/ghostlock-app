package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Covers [KsudLibrary]: the canonical name wins, and a renamed ksud is still
 * found by shape (large ELF executable) while JNI bridges next to it are not.
 */
class KsudLibraryTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val directory: File by lazy { folder.newFolder("lib-arm64") }

    /** Minimal ELF::ET_DYN with one PT_INTERP program header. */
    private fun elf(withInterpreter: Boolean, size: Long): File {
        val headerSize = 64
        val entrySize = 56
        val entries = 2
        val bytes = ByteArray(maxOf(headerSize + entries * entrySize, size.toInt()))
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2 /* ELFCLASS64 */
        bytes[5] = 1 /* little endian */
        val order = ByteOrder.LITTLE_ENDIAN
        ByteBuffer.wrap(bytes, 0x10, 2).order(order).putShort(3) /* e_type = ET_DYN */
        ByteBuffer.wrap(bytes, 0x20, 8).order(order).putLong(headerSize.toLong()) /* e_phoff */
        ByteBuffer.wrap(bytes, 0x36, 2).order(order).putShort(entrySize.toShort()) /* e_phentsize */
        ByteBuffer.wrap(bytes, 0x38, 2).order(order).putShort(entries.toShort()) /* e_phnum */
        /* ph[0] = PT_LOAD, ph[1] = PT_INTERP (the interpreter header). */
        ByteBuffer.wrap(bytes, headerSize, 4).order(order).putInt(1)
        ByteBuffer.wrap(bytes, headerSize + entrySize, 4).order(order)
            .putInt(if (withInterpreter) 3 else 1)
        val file = File(directory, "lib${System.nanoTime()}.so")
        file.writeBytes(bytes)
        return file
    }

    @Test
    fun `canonical libksud name wins without inspecting the file`() {
        val canonical = File(directory, KsudLibrary.CANONICAL_NAME).apply { writeText("stub") }
        assertEquals(canonical, KsudLibrary.find(directory))
    }

    @Test
    fun `renamed ksud is found by shape`() {
        /* SukiSU Ultra v4.3.0-r2 ships libtqqfthevwb.so at 6,102,016 bytes,
         * next to a 248,616-byte kptools helper that is also executable. */
        val bridge = elf(withInterpreter = false, size = 15_336)
        val kptools = elf(withInterpreter = true, size = 248_616)
        val ksud = elf(withInterpreter = true, size = 6_102_016)
        assertEquals(ksud, KsudLibrary.find(directory))
        assertTrue(bridge.isFile && kptools.isFile)
    }

    @Test
    fun `small executable helper is not mistaken for ksud`() {
        /* A manager whose APK ships no ksud still has an executable JNI
         * bridge; the size floor must make the lookup abstain. */
        elf(withInterpreter = true, size = 17_032)
        assertNull(KsudLibrary.find(directory))
    }

    @Test
    fun `large non-ELF file is not mistaken for ksud`() {
        File(directory, "libaudio_asset.so").writeBytes(ByteArray(4_000_000) { 0x41 })
        assertNull(KsudLibrary.find(directory))
    }

    @Test
    fun `empty and missing directories are tolerated`() {
        assertNull(KsudLibrary.find(null))
        assertNull(KsudLibrary.find(folder.newFolder("empty")))
        assertFalse(KsudLibrary.hasInterpreter(File(directory, "absent.so")))
    }
}
