/****************************************************************************
 * boards/arm/qemu/qemu-armv7a/scripts/dramboot.ld
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#include <nuttx/config.h>

OUTPUT_ARCH(arm)
ENTRY(__start)

MEMORY
{
  ROM (rx) : ORIGIN = CONFIG_FLASH_START, LENGTH = CONFIG_FLASH_SIZE
  RAM (rwx): ORIGIN = CONFIG_RAM_START,   LENGTH = CONFIG_RAM_SIZE
}

SECTIONS
{

  /* where the global variable out-of-bounds detection information located */

#ifdef CONFIG_MM_KASAN_GLOBAL
  .kasan.unused : {
    *(.data..LASANLOC*)
  }
  .kasan.global : {
    KEEP (*(.data..LASAN0))
    KEEP (*(.data.rel.local..LASAN0))
  }
  .kasan.shadows : {
    *(.kasan.shadows)
  }
#endif

  .text : {
      _stext = .;            /* Text section */
      __text_start = .;
      *(.vectors)
      *(.text*)
      *(.fixup)
      *(.gnu.warning)
  } > ROM

  . = ALIGN(4096);

  .init_section : {
      _sinit = ABSOLUTE(.);
      KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
      KEEP(*(.init_array EXCLUDE_FILE(*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o) .ctors))
      _einit = ABSOLUTE(.);
      . = ALIGN(4096);
      _etext = .; /* End_1 of .text */
      _sztext = _etext - _stext;
  } > ROM

  .ARM.extab :
  {
      *(.ARM.extab*)
  } > ROM

  /* .ARM.exidx is sorted, so has to go in its own output section.  */

  PROVIDE_HIDDEN (__exidx_start = .);
  .ARM.exidx :
  {
      *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } > ROM
  PROVIDE_HIDDEN (__exidx_end = .);

  .rodata : {
      _srodata = .;          /* Read-only data */
      *(.rodata*)
      *(.data.rel.ro*)
      KEEP(*(SORT(.scattered_array*)));
      . = ALIGN(4096);
      _erodata = .;
  } > ROM

  _eronly = LOADADDR(.data);
  .data : {                    /* Data */
      _sdata = .;
      *(.data*)
      . = ALIGN(8);
      __start_impls = .;
      *(.impls)
      KEEP(*(.impls))
      . = ALIGN(4);
      __stop_impls = .;
      _edata = .;
  } > RAM AT > ROM

  .noinit : {
      _snoinit = ABSOLUTE(.);
      *(.noinit*)
      _enoinit = ABSOLUTE(.);
  } > RAM

  /* Keep .bss in a PT_LOAD of its own.
   *
   * When .bss lands in the same program header as .data, that header has
   * p_filesz ~= 3.5 KB and p_memsz ~= 600 KB, and an ELF loader has to
   * materialise the difference as zeros AT THE SEGMENT'S PHYSICAL ADDRESS --
   * which for this board is the machine's flash aperture, because .data is
   * `AT > ROM`. QEMU 11 pushes those ~600 KB through the flash device one
   * store at a time: measured ~31 KB/s, i.e. ~19.6 s of emulator work before
   * the guest executes its first instruction. QEMU 6.2 does not. Splitting
   * .bss out gives it p_filesz == 0, so the loader has nothing to load and
   * skips it; the guest still clears .bss itself, as it always did.
   *
   * Whether the split happened used to be an accident of alignment: ld starts
   * a new segment only when .bss's VMA is not contiguous with the end of the
   * preceding section, so an image whose .data size was a multiple of .bss's
   * 16-byte alignment got the slow layout and one 8 bytes larger got the fast
   * one. Ten of twelve nano-ros images landed on the slow side.
   *
   * The ALIGN() forces that gap unconditionally (+1 before rounding, so a
   * .data that is already aligned still moves), costing <= 15 bytes of RAM.
   * The explicit AT is required and is not cosmetic: without it ld gives the
   * section LMA == VMA in RAM, and an image built that way boots but cannot
   * open its zenoh session. Keeping the LMA on the ROM run reproduces exactly
   * the layout the naturally-split images already had.
   */
  .bss ALIGN(ADDR(.noinit) + SIZEOF(.noinit) + 1, 16) :
       AT (LOADADDR(.noinit) + SIZEOF(.noinit)) {  /* BSS */
       _sbss = .;
       *(.bss*)
       . = ALIGN(4096);
       _ebss = .;
  } > RAM

  /* Sections to be discarded */
  /DISCARD/ : {
       *(.exit.text)
       *(.exit.data)
       *(.exitcall.exit)
  }

  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment 0 : { *(.comment) }
}

