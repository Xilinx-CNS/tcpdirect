/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** List of ZF attributes */

/*
\**************************************************************************/

#include <zf_internal/tcp_opt.h>
#include <zf_internal/private/attr_tmpl_private.h>


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

ZF_ATTR(bitmask, log_level, stable, ZF_LCL_ALL_ERR,
        "ERR-level on all components",
        "zf_stack",

        "Bitmask to enable different log message levels for each logging "
        "component.  The log message level for each component is specified "
        "using a separate 4 bit nibble within the bitmask.  The value of "
        "each nibble is a bitwise combination of:\n "
        "0(none),\n "
        "0x1(errors),\n "
        "0x2(warnings),\n "
        "0x4(info),\n "
        "0x8(trace - debug build only).\n "
        "\n "
        "The following components are available:\n "
        "stack (bits 0-3),\n "
        "TCP-rx (bits 4-7),\n "
        "TCP-tx (bits 8-11),\n "
        "TCP-connection (bits 12-15),\n "
        "UDP-rx (bits 16-19),\n "
        "UDP-tx (bits 20-23),\n "
        "UDP-connection (bits 24-27),\n "
        "muxer (bits 28-31),\n "
        "pool (bits 32-35),\n "
        "fast-path (bits 36-39),\n "
        "timers (bits 40-43),\n "
        "filters (bits 44-47),\n "
        "cplane (bits 48-51).\n "
        "\n "
        "E.g. 0xfff0 will enable all TCP related logging and disable all other "
        "logging.")

ZF_ATTR(int, log_format, stable, ZF_LF_STACK_NAME | ZF_LF_TCP_TIME,
        "stack name and tcp time",
        "zf_stack",

        "Bitmask to set the format of log messages. Combination of flags:\n "
        "ZF_LF_STACK_NAME (0x1),\n "
        "ZF_LF_FRC(0x2),\n "
        "ZF_LF_TCP_TIME(0x4),\n "
        "ZF_LF_PROCESS(0x8).")

ZF_ATTR(str, log_file, stable, NULL, "(stderr)",
        "zf_stack",

        "Use this file instead of stderr for log messages.")

/**********************************************************************
 * Generic attributes.
 */

ZF_ATTR(str, name, stable, NULL, "(none)",
        "zf_stack,zf_pool,zf_vi",

        "The object name.  The object name has a maximum length of "
        "20 characters.  Object names are visible in log messages, "
        "but have no other effect.")

/**********************************************************************
 * zf_stack attributes.
 */

ZF_ATTR(str, interface, stable, NULL, "none",
        "zf_stack",

        "Use this interface name as zf_stack interface.")

ZF_ATTR(int, max_udp_rx_endpoints, stable, 64, NULL,
        "zf_stack",

        "Sets the maximum number of UDP RX endpoints (i.e. struct zfur). "
        "This can be a value up to 64 (which is also the default).")

ZF_ATTR(int, max_udp_tx_endpoints, stable, 64, NULL,
        "zf_stack",

        "Sets the maximum number of UDP TX endpoints (i.e. struct zfut). "
        "This can be a value up to 64 (which is also the default).`")

ZF_ATTR(int, max_tcp_endpoints, stable, 64, NULL,
        "zf_stack",

        "Sets the maximum number of TCP endpoints (i.e. struct zft). "
        "This can be a value up to 64 (which is also the default).")

ZF_ATTR(int, max_tcp_listen_endpoints, stable, 16, NULL,
        "zf_stack",

        "Sets the maximum number of TCP listen endpoints (i.e. struct zftl). "
        "This can be a value up to 64.")

ZF_ATTR(int, max_tcp_syn_backlog, stable, 32,
        "net.ipv4.tcp_max_syn_backlog",
        "zf_stack",

        "Sets the maximum number of half-open connections maintained in the "
        "stack.")

ZF_ATTR(int, tcp_delayed_ack, stable, 1, NULL,
        "zf_stack",

        "Enable TCP delayed ACK (\"on\" by default).")

ZF_ATTR(int, tcp_wait_for_time_wait, stable, 0, NULL,
        "zf_stack",

        "Do not consider a stack to be quiescent if there are any TCP zockets "
        "in the TIME_WAIT state. (\"off\" by default).")


ZF_ATTR(int, tcp_timewait_ms, stable, ZF_TCP_TIMEWAIT_TIME_MS,
        "net.ipv4.tcp_fin_timeout",
        "zf_stack",

        "Length of TCP TIME-WAIT timer in ms.")

ZF_ATTR(int, tcp_finwait_ms, stable, ZF_TCP_TIMEWAIT_TIME_MS,
        "net.ipv4.tcp_fin_timeout",
        "zf_stack",

        "Length of TCP FIN-WAIT-2 timer in ms, 0 - disabled.")

/* tcp_syn_retries, tcp_synack_retries and tcp_retries default values are one
 * lower than the Linux equivalents because Linux counts transmissions and
 * TCPDirect counts retransmissions. */
ZF_ATTR(int, tcp_syn_retries, stable, 5,
        "net.ipv4.tcp_syn_retries",
        "zf_stack",

        "The maximum number of TCP SYN retransmits during zft_connect().")

ZF_ATTR(int, tcp_synack_retries, stable, 4,
        "net.ipv4.tcp_synack_retries",
        "zf_stack",

        "The maximum number of TCP SYN-ACK retransmits before incoming "
        "connection is dropped.")

ZF_ATTR(int, tcp_retries, stable, 14,
        "net.ipv4.tcp_retries2",
        "zf_stack",

        "The maximum number of TCP retransmits if data is not acknowledged "
        "by the network peer in general case. See also tcp_synack_retries, "
        "tcp_syn_retries.")

ZF_ATTR(int, tcp_initial_cwnd, stable, 0, "10 * MSS",
        "zf_stack",

        "The initial congestion window for new TCP zockets.")

ZF_ATTR(int, tcp_alt_ack_rewind, stable, 65536, "64K",
        "zf_stack",

        "The maximum number of bytes by which outgoing ACKs will be allowed "
        "to go backwards when sending an alternative queue.")

ZF_ATTR(int, arp_reply_timeout, stable, 1000, "1000",
        "zf_stack",

        "Maximum time to wait for ARP replies, in microseconds (approx).")

ZF_ATTR(int, udp_ttl, stable, 64, "64",
        "zf_socket",

        "Value of TTL field (Time To Live) for outgoing UDP packets "
        "(valid range 1-255).")


/**********************************************************************
 * zf_vi attributes.
 */


ZF_ATTR(int, rx_ring_max, stable, -1, "512",
        "zf_vi",

        "Set the size and maximum fill level of the RX descriptor ring, which "
        "provides buffering between the network adapter and software.  The "
        "RX ring sizes supported are 512, 1024, 2048 and 4096.  The "
        "\attrref{n_bufs} attribute may need to be increased when changing "
        "this value. 0 disables RX path.")


ZF_ATTR(int, reactor_spin_count, stable, 128, NULL,
        "zf_stack",

        "Sets how many iterations of the event processing loop "
        "zf_reactor_perform() will make (in the absence of any events) "
        "before returning. The default value makes zf_reactor_perform() "
        "briefly spin if there are no new events present. A higher number "
        "can give better latency, however zf_reactor_perform() will take "
        "more time to return when no new events are present. The minimum "
        "value is 1, which disables spinning. "

        "This attribute also affects the cost of zf_muxer_wait() when invoked "
        "with timeout_ns=0.")


ZF_ATTR(int, rx_ring_refill_batch_size, stable, 16, NULL,
        "zf_stack",

        "Sets the number of packet buffers rx ring is refilled with on each "
        "zf_reactor_perform() call.  Must be multiple of 8.")


ZF_ATTR(int, rx_ring_refill_interval, stable, 1, NULL,
        "zf_stack",

        "Sets the frequency of rx buffer ring refilling during inner "
        "zf_reactor_perform() loop.  Set to 1 to have the ring refilled at "
        "each iteration.")


ZF_ATTR(int, tx_ring_max, stable, 512, NULL,
        "zf_vi",

        "Set the size of the TX descriptor ring, which provides buffering "
        "between the software and the network adaptor.  The requested value "
        "is rounded up to the next size supported by the adapter.  At time "
        "of writing the ring sizes supported are 512, 1024 and 2048.  The "
        "\attrref{n_bufs} attribute may need to be increased when changing "
        "this value. 0 disables TX path.")


ZF_ATTR(int, alt_buf_size, stable, 40960, NULL,
        "zf_vi",

        "Amount of NIC-side buffer space to allocate for use with TCP "
        "alternatives on this VI.")

ZF_ATTR(int, alt_count, stable, 0, NULL,
        "zf_vi",

        "Number of TCP alternatives to allocate on this VI.  Not supported on "
        "stacks running on bonded network interfaces.")

ZF_ATTR(int, rx_timestamping, stable, 0, NULL,
        "zf_vi",

        "Add timestamps to received packets. \"off\" by default.")

ZF_ATTR(int, tx_timestamping, stable, 0, NULL,
        "zf_vi",

        "Report timestamps for transmitted packets. \"off\" by default.")

ZF_ATTR(int, pio, stable, 3, NULL,
        "zf_vi",

        "Enable/Disable PIO buffers. "
        "0: don't use PIO,\n "
        "1: PIO if supported by hardware and resource available, "
        "no warning if not,\n "
        "2: PIO if supported by hardware and resource available, "
        "warn if not,\n "
        "3: PIO if supported by hardware and resource available, "
        "warn if not supported, else fail + error (default).\n "
        "\n "
        "Note that warnings are disabled by default. If setting this "
        "attribute to 2 or 3, then set bit 1 of the \attrref{log_level} "
        "for the stack component to enable these warnings." )

ZF_ATTR(int, ctpio, stable, 1, NULL,
        "zf_vi",

        "Enable/Disable CTPIO. "
        "0: don't use CTPIO,\n "
        "1: CTPIO if available, no warning if not (default),\n "
        "2: CTPIO if available, warn if not,\n "
        "3: CTPIO else fail + error messages.\n "
        "\n "
        "Note that warnings are disabled by default. If setting this "
        "attribute to 2, then bit 1 of the \attrref{log_level} attribute must "
        "also be set to enable warnings for the stack component." )

ZF_ATTR(str, ctpio_mode, stable, "sf-np", "sf-np",
        "zf_vi",

        "Set the CTPIO mode to use. Set to:\n "
        "'sf' for store-and-forward;\n "
        "'ct' for cut-through;\n "
        "'sf-np' to guarantee that poisoned frames are never emitted.")

ZF_ATTR(int, ctpio_max_frame_len, beta, -1, NULL,
        "zf_vi",

        "Sets the maximum frame length for the CTPIO low-latency transmit "
        "mechanism.  Packets up to this length will use CTPIO, if CTPIO is "
        "supported by the adapter and if CTPIO is enabled (see the "
        "\attrref{ctpio} attribute).  Longer packets will use PIO and/or DMA.")

ZF_ATTR(int, force_separate_tx_vi, beta, 0, NULL,
        "zf_vi",

        "Force seting up separate vi with dedicated evq for tx. "
        "The feature is unstable."
        )

ZF_ATTR(str, rx_datapath, stable, "express", NULL,
        "zf_vi",

        "Options for the rx_datapath mode to use where multiple datapaths are available. \n"
        "Valid options are:\n"
        " 'express'\n"
        " 'enterprise'\n")

ZF_ATTR(int, phys_address_mode, stable, 0, NULL,
        "zf_vi",

        "This option enables physical addressing mode.  This makes the DMA mapped \n"
        "addresses directly visible to user space, which should only be used where \n"
        "applications are trusted. The sfc_char module parameter phys_mode_gid can \n"
        "be used to control which users are able to use physical addressing mode. \n"
        "\n"
        " 1 - Enable physical addressing mode. Inherently unsafe; no address space \n"
        "     separation between different stacks or net driver packets.\n"
        "\n"
        "0 - Don't enable physical addressing mode. User space sees virtual addresses \n"
        "    which are translated by hardware or in the kernel.")

ZF_ATTR(int, shrub_controller, stable, -1, NULL,
        "zf_vi",

        "Enable shrub controller on this VI.  This is required to enable zf_stacks \n"
        "to attach to a given shared controller on given x4 platforms. \n"
        "Possible values here include -1 for default no shrub controller, \n"
        "or a value from 0 to 9999 to connect to a particular controller. \n"
        "TCPDirect expects the shrub controller to be spawned manually separately to \n"
        "the application using the zf_stack.")

ZF_ATTR(str, tph_mode, stable, "off", "off",
        "zf_vi",

        "Set the PCIe TPH mode to use for SDCI. Set to:\n"
        " 'off' to disable use of TPH\n"
        " 'nost' to enable use of TPH without steering tags\n"
        " 'st' to enable use of TPH with steering tags\n"
        "Using steering tags is recommended on platforms that support it.")

/**********************************************************************
 * zf_pool attributes.
 */

ZF_ATTR(int, n_bufs, stable, 0, NULL,
        "zf_pool",

        "Number of packet buffers to allocate for the stack.  The optimal "
        "value for this parameter depends on the size of the RX and TX "
        "queues, the total number of zockets in the stack, the number of "
        "alternatives in use and the frequency at which the application polls "
        "the stack and reads pending data from zockets.  0 - use maximum the "
        "stack with given parameters can use." )

