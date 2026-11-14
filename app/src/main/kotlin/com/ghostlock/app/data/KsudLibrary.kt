package com.ghostlock.app.data

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Resolves the `ksud` executable a root-manager APK ships in its native library
 * directory.
 *
 * Managers historically package it as `libksud.so`, which is why the scan used
 * to match that name. SukiSU Ultra breaks the assumption: its release CI
 * rewrites the literal on every build
 * (`build-manager.yml`: `KSUD_LIB="lib$(rand_alpha 10).so"`, then a repo-wide
 * `sed` of `"libksud.so"`), so a real install carries a different name — the
 * released v4.3.0-r2 APK ships `libtqqfthevwb.so`. A name match therefore
 * reports "no ksud" for a manager that can load modules fine.
 *
 * A packaged ksud keeps two structural properties the neighbouring JNI bridges
 * lack: it is an ELF executable (`PT_INTERP`, a dynamic loader interpreter) and
 * it is multi-megabyte. Measured arm64 native library dirs:
 *
 * | APK                | ksud file            | size       | PT_INTERP |
 * | ------------------ | -------------------- | ---------- | --------- |
 * | KernelSU v3.3.1    | `libksud.so`         | 4,990,848  | yes       |
 * | BakaSU v4.2.0-rc3  | `libksud.so`         | 5,679,064  | yes       |
 * | SukiSU v4.3.0-r2   | `libtqqfthevwb.so`   | 6,102,016  | yes       |
 * | KowSU (CI build)   | absent               | -          | -         |
 *
 * The bridges next to them are 9-250 KB; SukiSU's `libkptools.so` is the only
 * other executable one, at 248,616 bytes, so size still disambiguates.
 */
object KsudLibrary {
    const val CANONICAL_NAME = "libksud.so"

    /**
     * Size floor for the structural match. Every measured ksud is >= 3.4 MB;
     * the floor makes the rule abstain on a manager whose APK ships no ksud at
     * all instead of returning a JNI bridge. Measured: KowSU's plain Gradle
     * build only has 10-17 KB libraries and no ksud.
     */
    private const val MIN_STRUCTURAL_BYTES = 1_000_000L

    /** `p_type` of the dynamic-linker interpreter header. */
    private const val PT_INTERP = 3
    private const val ELF_HEADER_BYTES = 64
    private const val MAX_PROGRAM_HEADERS = 512

    private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

    /** ksud shipped under [nativeLibraryDir], or null when the app ships none. */
    fun find(nativeLibraryDir: File?): File? {
        if (nativeLibraryDir == null) return null
        val libs = nativeLibraryDir.listFiles { file -> file.isFile && file.name.endsWith(".so") }
            ?: return null
        libs.firstOrNull { it.name == CANONICAL_NAME }?.let { return it }
        return libs.asSequence()
            .filter { it.length() >= MIN_STRUCTURAL_BYTES && hasInterpreter(it) }
            .maxByOrNull { it.length() }
    }

    /** True when [file] is an ELF whose program headers include `PT_INTERP`. */
    fun hasInterpreter(file: File): Boolean = runCatching {
        RandomAccessFile(file, "r").use { handle ->
            if (handle.length() < ELF_HEADER_BYTES) return@use false
            val header = ByteArray(ELF_HEADER_BYTES)
            handle.readFully(header)
            if (!header.copyOfRange(0, ELF_MAGIC.size).contentEquals(ELF_MAGIC)) return@use false
            /* EI_DATA at 0x05: only little-endian targets ship on Android. */
            if (header[5] != 1.toByte()) return@use false
            val order = ByteOrder.LITTLE_ENDIAN
            /* ELF64 and ELF32 put the e_phoff/e_phentsize/e_phnum trio at
             * different offsets; EI_CLASS at 0x04 selects the table. */
            val is64 = header[4] == 2.toByte()
            val programOffset = if (is64) {
                buffer(header, 0x20, 8, order).long
            } else {
                buffer(header, 0x1C, 4, order).int.toLong() and 0xFFFF_FFFFL
            }
            val entrySize = shortAt(header, if (is64) 0x36 else 0x2A, order)
            val entryCount = shortAt(header, if (is64) 0x38 else 0x2C, order)
            if (entrySize < 32 || entryCount <= 0 || entryCount > MAX_PROGRAM_HEADERS) return@use false
            if (programOffset <= 0) return@use false
            if (programOffset + entryCount.toLong() * entrySize > handle.length()) return@use false
            val entry = ByteArray(entrySize)
            for (index in 0 until entryCount) {
                handle.seek(programOffset + index.toLong() * entrySize)
                handle.readFully(entry)
                /* p_type is a 4-byte integer at offset 0 for both classes. */
                if (buffer(entry, 0, 4, order).int == PT_INTERP) return@use true
            }
            false
        }
    }.getOrDefault(false)

    private fun shortAt(source: ByteArray, offset: Int, order: ByteOrder): Int =
        buffer(source, offset, 2, order).short.toInt() and 0xFFFF

    private fun buffer(source: ByteArray, offset: Int, length: Int, order: ByteOrder): ByteBuffer =
        ByteBuffer.wrap(source, offset, length).order(order)
}
