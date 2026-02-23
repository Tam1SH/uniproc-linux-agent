
// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/socket.h#L188
pub const AF_UNSPEC: u16    = 0;
pub const AF_UNIX: u16      = 1;  /* Unix domain sockets          */
pub const AF_LOCAL: u16     = 1;  /* POSIX name for AF_UNIX       */
pub const AF_INET: u16      = 2;  /* Internet IP Protocol         */
pub const AF_AX25: u16      = 3;  /* Amateur Radio AX.25          */
pub const AF_IPX: u16       = 4;  /* Novell IPX                   */
pub const AF_APPLETALK: u16 = 5;  /* AppleTalk DDP                */
pub const AF_NETROM: u16    = 6;  /* Amateur Radio NET/ROM         */
pub const AF_BRIDGE: u16    = 7;  /* Multiprotocol bridge         */
pub const AF_ATMPVC: u16    = 8;  /* ATM PVCs                     */
pub const AF_X25: u16       = 9;  /* Reserved for X.25 project    */
pub const AF_INET6: u16     = 10; /* IP version 6                 */
pub const AF_ROSE: u16      = 11; /* Amateur Radio X.25 PLP       */
pub const AF_DECnet: u16    = 12; /* Reserved for DECnet project  */
pub const AF_NETBEUI: u16   = 13; /* Reserved for 802.2LLC project*/
pub const AF_SECURITY: u16  = 14; /* Security callback pseudo AF  */
pub const AF_KEY: u16       = 15; /* PF_KEY key management API    */
pub const AF_NETLINK: u16   = 16;
pub const AF_ROUTE: u16     = AF_NETLINK; /* Alias to emulate 4.4BSD */
pub const AF_PACKET: u16    = 17; /* Packet family                */
pub const AF_ASH: u16       = 18; /* Ash                          */
pub const AF_ECONET: u16    = 19; /* Acorn Econet                 */
pub const AF_ATMSVC: u16    = 20; /* ATM SVCs                     */
pub const AF_RDS: u16       = 21; /* RDS sockets                  */
pub const AF_SNA: u16       = 22; /* Linux SNA Project (nutters!) */
pub const AF_IRDA: u16      = 23; /* IRDA sockets                 */
pub const AF_PPPOX: u16     = 24; /* PPPoX sockets                */
pub const AF_WANPIPE: u16   = 25; /* Wanpipe API Sockets          */
pub const AF_LLC: u16       = 26; /* Linux LLC                    */
pub const AF_IB: u16        = 27; /* Native InfiniBand address    */
pub const AF_MPLS: u16      = 28; /* MPLS                         */
pub const AF_CAN: u16       = 29; /* Controller Area Network      */
pub const AF_TIPC: u16      = 30; /* TIPC sockets                 */
pub const AF_BLUETOOTH: u16 = 31; /* Bluetooth sockets            */
pub const AF_IUCV: u16      = 32; /* IUCV sockets                 */
pub const AF_RXRPC: u16     = 33; /* RxRPC sockets                */
pub const AF_ISDN: u16      = 34; /* mISDN sockets                */
pub const AF_PHONET: u16    = 35; /* Phonet sockets               */
pub const AF_IEEE802154: u16= 36; /* IEEE802154 sockets           */
pub const AF_CAIF: u16      = 37; /* CAIF sockets                 */
pub const AF_ALG: u16       = 38; /* Algorithm sockets            */
pub const AF_NFC: u16       = 39; /* NFC sockets                  */
pub const AF_VSOCK: u16     = 40; /* vSockets                     */
pub const AF_KCM: u16       = 41; /* Kernel Connection Multiplexor*/
pub const AF_QIPCRTR: u16   = 42; /* Qualcomm IPC Router          */
pub const AF_SMC: u16       = 43; /* smc sockets (reserve PF_SMC) */
pub const AF_XDP: u16       = 44; /* XDP sockets                  */
pub const AF_MCTP: u16      = 45; /* Management component transport protocol */
pub const AF_MAX: u16       = 46;

//https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L64
pub const SOCK_STREAM: i16    = 1;
pub const SOCK_DGRAM: i16     = 2;
pub const SOCK_RAW: i16       = 3;
pub const SOCK_RDM: i16       = 4;
pub const SOCK_SEQPACKET: i16 = 5;
pub const SOCK_DCCP: i16      = 6;
pub const SOCK_PACKET: i16    = 10;

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/uapi/linux/in.h#L29
pub const IPPROTO_IP: u16       = 0;   /* Dummy protocol for TCP               */
pub const IPPROTO_ICMP: u16     = 1;   /* Internet Control Message Protocol    */
pub const IPPROTO_IGMP: u16     = 2;   /* Internet Group Management Protocol   */
pub const IPPROTO_IPIP: u16     = 4;   /* IPIP tunnels (older KA9Q tunnels)    */
pub const IPPROTO_TCP: u16      = 6;   /* Transmission Control Protocol        */
pub const IPPROTO_EGP: u16      = 8;   /* Exterior Gateway Protocol            */
pub const IPPROTO_PUP: u16      = 12;  /* PUP protocol                         */
pub const IPPROTO_UDP: u16      = 17;  /* User Datagram Protocol               */
pub const IPPROTO_IDP: u16      = 22;  /* XNS IDP protocol                     */
pub const IPPROTO_TP: u16       = 29;  /* SO Transport Protocol Class 4        */
pub const IPPROTO_DCCP: u16     = 33;  /* Datagram Congestion Control Protocol */
pub const IPPROTO_IPV6: u16     = 41;  /* IPv6-in-IPv4 tunnelling              */
pub const IPPROTO_RSVP: u16     = 46;  /* RSVP Protocol                        */
pub const IPPROTO_GRE: u16      = 47;  /* Cisco GRE tunnels (rfc 1701,1702)    */
pub const IPPROTO_ESP: u16      = 50;  /* Encapsulation Security Payload       */
pub const IPPROTO_AH: u16       = 51;  /* Authentication Header protocol       */
pub const IPPROTO_MTP: u16      = 92;  /* Multicast Transport Protocol         */
pub const IPPROTO_BEETPH: u16   = 94;  /* IP option pseudo header for BEET     */
pub const IPPROTO_ENCAP: u16    = 98;  /* Encapsulation Header                 */
pub const IPPROTO_PIM: u16      = 103; /* Protocol Independent Multicast       */
pub const IPPROTO_COMP: u16     = 108; /* Compression Header Protocol          */
pub const IPPROTO_L2TP: u16     = 115; /* Layer 2 Tunnelling Protocol          */
pub const IPPROTO_SCTP: u16     = 132; /* Stream Control Transport Protocol    */
pub const IPPROTO_UDPLITE: u16  = 136; /* UDP-Lite (RFC 3828)                  */
pub const IPPROTO_MPLS: u16     = 137; /* MPLS in IP (RFC 4023)                */
pub const IPPROTO_ETHERNET: u16 = 143; /* Ethernet-within-IPv6 Encapsulation   */
pub const IPPROTO_RAW: u16      = 255; /* Raw IP packets                       */
pub const IPPROTO_MPTCP: u16    = 262; /* Multipath TCP connection             */

pub const IPPROTO_MAX: u16      = 263;


// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/uapi/linux/stat.h#L9
pub const S_IFMT: u16   = 0o170000; /* bit mask for the file type bit field */
pub const S_IFSOCK: u16 = 0o140000; /* socket */
pub const S_IFLNK: u16  = 0o120000; /* symbolic link */
pub const S_IFREG: u16  = 0o100000; /* regular file */
pub const S_IFBLK: u16  = 0o060000; /* block device */
pub const S_IFDIR: u16  = 0o040000; /* directory */
pub const S_IFCHR: u16  = 0o020000; /* character device */
pub const S_IFIFO: u16  = 0o010000; /* FIFO */
pub const S_ISUID: u16  = 0o004000; /* set-user-ID bit */
pub const S_ISGID: u16  = 0o002000; /* set-group-ID bit (see below) */
pub const S_ISVTX: u16  = 0o001000; /* sticky bit (see below) */


// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/mm_types_task.h#L31
pub const MM_FILEPAGES:   usize = 0; /* Resident file mapping pages */
pub const MM_ANONPAGES:   usize = 1; /* Resident anonymous pages */
pub const MM_SWAPENTS:    usize = 2; /* Anonymous swap entries */
pub const MM_SHMEMPAGES:  usize = 3; /* Resident shared memory pages */
pub const NR_MM_COUNTERS: usize = 4;
