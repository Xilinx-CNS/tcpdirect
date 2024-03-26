/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * ZF_ATTR(type, name, status, default, objects, doc)
 *
 *        type: int or str
 *        name: name of attribute
 *      status: stable, stable_expert, hidden, beta or unstable
 * default_val: default value of attribute (must be NULL for str attrs)
 * default_doc: description of default, or NULL
 *     objects: what type(s) of objects the attribute applies to
 *         doc: documentation
 */


/**********************************************************************
 * global attributes.
 */

ZF_ATTR(int, emu, hidden, 0, "(none)",
        "zf",

        "Instead of hardware an in SW emulation is used as loopback "
        "Values: 0(disabled), 1(loop packets between two stacks), "
        "2(loop packets back to the same stack), "
        "3(use TUN device to exchange the emulated VI traffic through)")

ZF_ATTR(str, emu_tun_ip, hidden, NULL, "(tun interface address xor 3)",
        "zf",

        "Local address of zf stack, should be different than "
        "the address of the tun device but in the same local network.")

ZF_ATTR(int, emu_vlan, hidden, 0xFFFF, "(no vlan)",
        "zf",

        "Tells emulation to pretend to run on specific vlan.  "
        "Does not apply to TUN emulation.")

ZF_ATTR(int, emu_mtu, hidden, 1500, "(standrad MTU of 1500)",
        "zf",

        "Tells emulation to report given mtu to the app.")

ZF_ATTR(int, emu_pio, hidden, 1, "Available",
        "zf",

        "Whether the emulation has a PIO buffer available. "
        "Values: 0 - PIO not available, 1 - PIO available")

ZF_ATTR(str, emu_shmname, hidden, NULL, "(Use interface name)",
        "zf",

        "Suffix for name for SHM file used by emulator.")

ZF_ATTR(int, log_to_kmsg, hidden, 0,
        "Disabled, i.e. log to stderr",
        "zf",

        "Write all logging messages to /dev/kmsg.")

ZF_ATTR(int, max_sbufs, hidden, 1024,
        "sbufs",
        "zf",

        "Set the maximum number of superbufs zf_emu may use")

/**********************************************************************
 * Socket shim attributes.  N.B.: These are not used directly, and
 * their defaults never take effect, but instead, the shim parses the
 * ZF_ATTR environment variable itself.
 */

ZF_ATTR(int, emu_nic, hidden, 2, "(Medford2)",
        "zf",

        "Tells emulation to behave as a given NIC for RX and mixed VI. "
        "Values: 0 - huntington, 1 - Medford, 2 - Medford2, 3 - X3")

ZF_ATTR(int, tx_emu_nic, hidden, 2, "(Medford2)",
        "zf",
        "Tells emulation to behave as a given NIC on tx side. "
        "Values: 0 - huntington, 1 - Medford, 2 - Medford2, 3 - X3")

ZF_ATTR(str, zfss_implicit_host, unstable, NULL, NULL,
        "zfss",

        "host to use for implicit binds.")

ZF_ATTR(int, zfss_fd_table_size, unstable, 256, NULL,
        "zfss",

        "File descriptor table size.")

