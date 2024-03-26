#! /bin/bash -eu
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2020 Advanced Micro Devices, Inc.
#
# Used in the creation of the distributied TCPDirect library

src="$1"
dst="$2"
redef=$(dirname "${dst}")/redef

"${OBJCOPY}" \
    --strip-debug \
    --strip-unneeded \
    --discard-all \
    --localize-hidden \
    --wildcard \
    --localize-symbol="ef*" \
    --localize-symbol="ci*" \
    --localize-symbol="__ef*" \
    --localize-symbol="*zf_logger*" \
    --localize-symbol="onload_*" \
    --localize-symbol="*oo_cp*" \
    "$src" \
    "$dst"

# replace meaningful function name with a hash
nm "${dst}" | perl -MDigest::MD5 -ne \
      '@line = split;
       # Obfuscate if symbol not global or otherwise special, and not yet seen.
       $line[1] !~ /[A-Zur]/ && $seen{$line[2]}++ == 0 &&
         print "$line[2] __" . Digest::MD5::md5_hex(@line) . "\n"' > "${redef}"

"${OBJCOPY}"\
    --strip-debug \
    --strip-unneeded \
    --discard-all \
    --redefine-syms "${redef}" "${dst}"
