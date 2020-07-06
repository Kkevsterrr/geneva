# The following strategies have been learned as successful against the Great Firewall.
WORKING_STRATEGIES = [
    {
        "strategy"     : "\/",
        "success_rate" : .03,
        "description"  : "No strategy",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },

    # TCB Desync - High DataOfs
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:replace:25776},),)-",
        "success_rate" : .98,
        "description"  : "TCP Desync - Increment Dataofs - Corrupt Chksum",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-",
        "success_rate" : .98,
        "description"  : "TCP Desync - Increment Dataofs - Small TTL",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:flags:replace:FRAPUN},),)-",
        "success_rate" : .26,
        "description"  : "TCP Desync - Increment Dataofs - Invalid Flags",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-",
        "success_rate" : .94,
        "description"  : "TCP Desync - Increment Dataofs - Corrupt ACK",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-",
        "success_rate" : .98,
        "description"  : "TCP Desync - Increment Dataofs - Corrupt WScale",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    # TCB Desync - Load corruption
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-",
        "success_rate" : .98,
        "description"  : "TCP Desync - Invalid Payload - Corrupt Chksum",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8}(duplicate(fragment{tcp:-1:False},),),),)-",
        "success_rate" : .98,
        "description"  : "TCP Desync - Invalid Payload - Small TTL",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt}(duplicate(fragment{tcp:-1:False},),),),)-",
        "success_rate" : .93,
        "description"  : "TCP Desync - Invalid Payload - Corrupt ACK",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },

    # TCB Teardown (with RST)
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
        "success_rate" : .95,
        "description"  : "TCB Teardown - with RST - Corrupt Chksum, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-",
        "success_rate" : .51,
        "description"  : "TCB Teardown - with RST - Corrupt Chksum, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-",
        "success_rate" : .87,
        "description"  : "TCB Teardown - with RST - Small TTL, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:9},),)-",
        "success_rate" : .52,
        "description"  : "TCB Teardown - with RST - Small TTL, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-",
        "success_rate" : .86,
        "description"  : "TCB Teardown - with RST - Invalid md5Header, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:RA},),)-",
        "success_rate" : .44,
        "description"  : "TCB Teardown - with RST - Invalid md5Header, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    # Teardown with RST/ACK
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},))-",
        "success_rate" : .90,
        "description"  : "TCB Teardown - with RST/ACK - Corrupt Chksum, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:replace:27925},),)-",
        "success_rate" : .66,
        "description"  : "TCB Teardown - with RST/ACK - Corrupt Chksum, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-",
        "success_rate" : .94,
        "description"  : "TCB Teardown - with RST/ACK - Small TTL, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},),)-",
        "success_rate" : .57,
        "description"  : "TCB Teardown - with RST/ACK - Small TTL, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-",
        "success_rate" : .94,
        "description"  : "TCB Teardown - with RST/ACK - Invalid md5Header, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},),)-",
        "success_rate" : .48,
        "description"  : "TCB Teardown - with RST/ACK - Invalid md5Header, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},),)-",
        "success_rate" : .43,
        "description"  : "TCB Teardown - with RST/ACK - Corrupt ACK, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:ack:corrupt},))-",
        "success_rate" : .31,
        "description"  : "TCB Teardown - with RST/ACK - Corrupt ACK, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    # TCB Teardown w/ Invalid Flags
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))- ",
        "success_rate" : .89,
        "description"  : "TCB Teardown - Invalid Flags - Corrupt Chksum, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},),)-",
        "success_rate" : .48,
        "description"  : "TCB Teardown - Invalid Flags - Corrupt Chksum, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-",
        "success_rate" : .96,
        "description"  : "TCB Teardown - Invalid Flags - Small TTL, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{IP:ttl:replace:10},),)-",
        "success_rate" : .56,
        "description"  : "TCB Teardown - Invalid Flags - Small TTL, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-",
        "success_rate" : .94,
        "description"  : "TCB Teardown - Invalid Flags - Invalid md5Header, High Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:options-md5header:corrupt},),)-",
        "success_rate" : .55,
        "description"  : "TCB Teardown - Invalid Flags - Invalid md5Header, Low Percentage",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:A]-tamper{TCP:load:replace:a5z2}(tamper{TCP:flags:replace:CN},)-",
        "success_rate" : .00,
        "description"  : "TCB Teardown - Invalid Flags - Invalid Payload",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    # Segmentation
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:8:False}-|[TCP:flags:A]-tamper{TCP:seq:replace:2258679050}-",
        "success_rate" : .92,
        "description"  : "Segmentation - With ACK - Offsets, subvariant 1",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:8:False}-| [TCP:flags:A]-tamper{TCP:seq:replace:2258679050}(tamper{TCP:flags:replace:PA},)-",
        "success_rate" : .95,
        "description"  : "Segmentation - With ACK - Offsets, subvariant 2",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
        },
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-",
        "success_rate" : .98,
        "description"  : "Segmentation - Reassembly - Offsets, subvariant 1",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:4:True}(,fragment{tcp:19:True})-",
        "success_rate" : .96,
        "description"  : "Segmentation - Reassembly - Offsets, subvariant 2",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    # Hybrid Strategies
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \/",
        "success_rate" : .53,
        "description"  : "Hybrid Strategy - HTTP - Fragment and set Fin flag",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "china"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:68},),)-| \/",
        "success_rate" : 1,
        "description"  : "Hybrid Strategy - DNS Over TCP - Fragment and set Fin flag",
        "test_type"    : "dns_tcp",
        "server_side"  : False,
        "country"      : "china"
    },
    # Server-side strategies
    {
        "strategy"     : "[TCP:flags:SA]-duplicate(tamper{TCP:flags:replace:FREC}(duplicate,),tamper{TCP:flags:replace:FSEC})-| \/",
        "success_rate" : .43,
        "description"  : "Server-Side - Simultaneous Open",
        "test_type"    : "http",
        "server_side"  : True,
        "country"      : "china"
    },
    # DNS over UDP strategies
    {
        "strategy"     : "\/ [UDP:sport:53:2]-drop-",
        "success_rate" : .96,
        "description"  : "DNS - Drop first two bad responses",
        "test_type"    : "dns",
        "server_side"  : False,
        "country"      : "china"
    },
    # India HTTP strategies
    {
        "strategy"     : "[TCP:options-altchksum:]-tamper{TCP:options-uto:corrupt}(duplicate,)-| \/",
        "success_rate" : 1,
        "description"  : "Invalid Options",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:options-mss:]-tamper{TCP:options-md5header:corrupt}-| \/",
        "success_rate" : 1,
        "description"  : "Invalid Options",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:9},)-| \/",
        "success_rate" : 1,
        "description"  : "Increasing dataofs",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-|",
        "success_rate" : 1,
        "description"  : "IP length",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
        "success_rate" : 1,
        "description"  : "Segmentation",
        "test_type"    : "http",
        "server_side"  : False,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:flags:SA]-tamper{TCP:window:replace:98}-|",
        "success_rate" : 1,
        "description"  : "Server side",
        "test_type"    : "http",
        "server_side"  : True,
        "country"      : "india"
    },
    {
        "strategy"     : "[TCP:flags:PA]-fragment{tcp:-1:True}-|",
        "success_rate" : 1,
        "description"  : "Segmentation",
        "test_type"    : "kazakhstan_injected_https",
        "server_side"  : False,
        "country"      : "kazakhstan"
    },
    {
        "strategy"     : "[TCP:flags:PA]-duplicate(tamper{IP:len:replace:78},)-|",
        "success_rate" : 1,
        "description"  : "Segmentation Exploit - Small IP length",
        "test_type"    : "kazakhstan_injected_https",
        "server_side"  : False,
        "country"      : "kazakhstan"
    },
    {
        "strategy"     : "[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-|",
        "success_rate" : 1,
        "description"  : "Desync: load on second SYN",
        "test_type"    : "kazakhstan_injected_https",
        "server_side"  : False,
        "country"      : "kazakhstan"
    },
    {
        "strategy"     : "[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-|",
        "success_rate" : 1,
        "description"  : "TCB Turnaround",
        "test_type"    : "kazakhstan_injected_https",
        "server_side"  : False,
        "country"      : "kazakhstan"
    },
]

# Strategies that evade the lab censors
LAB_STRATEGIES = [
    {
        "strategy" : "[TCP:flags:A]-tamper{TCP:flags:replace:F}-| \/",
        "censors"  : ["censor6", "censor7", "censor8"],
        "description" : "Interrupts the 3-way handshake with a FIN. The server ignores the FIN, as \
                         the 3-way handshake has not been done yet, so there is no connection to teardown. \
                         Since the client's very next packet is a PSH-ACK, the ACK in this packet serves to \
                         complete the 3-way handshake, but the censor tears down it's TCB at the FIN."
    },
    {
        "strategy" : "[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt}(tamper{TCP:flags:replace:R},),)-| \/",
        "censors"  : ["censor6", "censor7"],
        "description" : "Tears down a TCB right after a 3-way handshake by injecting a RST packet."
    },
    {
        "strategy" : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/",
        "censors" : ["censor6", "censor7", "censor8", "censor8b"],
        "description" : "Creates a RST injection packet to tear down a TCB and corrupts the checksum, exploiting a censor \
                         that does not validate packet checksums."
    },
    {
        "strategy" : "\/ [TCP:dataofs:5]-drop-|",
        "censors" : ["censor2"],
        "description" : "RST Packets (at least those constructed with scapy) have a data offset of 5. This \
                         beats a censor that only sends RSTs to the client by dropping the RST packets."
    },
    {
        "strategy" : "\/ [TCP:flags:R]-drop-|",
        "censors" : ["censor2"],
        "description" : "Beats a censor that only sends RSTs to the client by dropping the RST packets."
    },
    {
        "strategy" : "\/ [TCP:window:8192]-drop-|",
        "censors" : ["censor2"],
        "description" : "RST Packets (at least those constructed with scapy) have a default window size of 8192. This \
                         beats a censor that only sends RSTs to the client by dropping the RST packets."
    },
    {
        "strategy" : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-| \/",
        "censors" : ["censor1", "censor2", "censor3", "censor5", "censor6", "censor7", "censor8", "censor8b", "censor9"],
        "description" : "Triggers a RST packet and SYN packet to be sent immediately after the 3-way handshake \
                         finishes. The server ignores the RST, as the chksum is corrupted, and ignores the SYN, \
                         as a connection is already up. The censor sees the RST and enters the resynchronization \
                         state, and the immediate follow-up SYN packet causes the TCB to be deschronized from the \
                         real connection."
    },
    {
        "strategy" : "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:seq:corrupt}(tamper{TCP:chksum:corrupt},),),))-| \/",

        "censors" : ["censor1", "censor2", "censor3", "censor5", "censor6", "censor7", "censor8", "censor8b", "censor9"],
        "description" : "Triggers a RST packet and SYN packet to be sent immediately after the 3-way handshake \
                         finishes. The server ignores the RST, as the chksum is corrupted, and ignores the SYN, \
                         as a connection is already up. The censor sees the RST and enters the resynchronization \
                         state, and the immediate follow-up SYN packet with a new seq causes the TCB to be deschronized from the \
                         real connection."
    },

    {
        "strategy" : "[TCP:flags:A]-tamper{TCP:dataofs:replace:0}-| \/",
        "censors" : ["censor1", "censor2", "censor3", "censor5", "censor9", "censor10"],
        "description" : "The dataofs field in the TCP header tells applications where the payload of the packet \
                         starts. By replacing the dataofs to 0 on a packet without a payload (ACK), it makes the \
                         TCP header look like data. Servers ignore this, but a censor that is trying to keep a TCB \
                         synchronized will be desynchronized from the connection when it gets a payload of an incorrect \
                         length."

    },
    {
        "strategy" : "[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \/",
        "censors" : ["censor1", "censor2", "censor3", "censor5", "censor9", "censor10"],
        "description" : "The dataofs field in the TCP header tells applications where the payload of the packet \
                         starts. By replacing the dataofs to 0 on a packet without a payload (ACK), it makes the \
                         TCP header look like data. Servers ignore this, but a censor that is trying to keep a TCB \
                         synchronized will be desynchronized from the connection when it gets a payload of an incorrect \
                         length. This strategy is functionally equivalent to the above strategy, but also preserves the \
                             original packet."

        },
]
