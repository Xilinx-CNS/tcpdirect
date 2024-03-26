/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */

/* Needed to compile onload driver superbuf code in tcpdirect test unit context.
 * Provides compatibility to allow building in user level code.
 */


#include "zf_emu_superbuf.h"
#include <../driver/linux_resource/efct_superbuf.c>
