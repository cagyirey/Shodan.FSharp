namespace Shodan.FSharp

exception ShodanWebException of string

type QueryOrder =
    | Ascending
    | Descending
    with 
        override x.ToString() = 
            match x with
            | Ascending -> "asc"
            | Descending -> "desc"

type QuerySort =
    | Votes
    | Timestamp

type GeoBounding =
    | Radius of float
    | Box of float * float
    with 
        override x.ToString() = 
            match x with
            | Radius r -> sprintf "%G" r 
            | Box(l, r) -> sprintf "%G,%G" l r

[<RequireQualifiedAccess>]
module private LinkType = 

    [<Literal>]
    let EthernetOrModem = "Ethernet or modem"

    [<Literal>]
    let TunnelOrVPN = "generic tunnel or VPN"

    [<Literal>]
    let DSL = "DSL"

    [<Literal>]
    let IPIPorSIT = "IPIP or SIT"

    [<Literal>]
    let SLIP = "SLIP"

    [<Literal>]
    let IPSecOrGRE = "IPSec or GRE"

    [<Literal>]
    let VLAN = "VLAN"

    [<Literal>]
    let JumboEthernet = "jumbo Ethernet"

    [<Literal>]
    let Google = "Google"

    [<Literal>]
    let GIF = "GIF"

    [<Literal>]
    let PPTP = "PPTP"

    [<Literal>]
    let Loopback = "loopback"

    [<Literal>]
    let AX25RadioModem = "AX.25 radio modem"


type Link =
    | EthernetOrModem
    | TunnelOrVPN
    | DSL
    | IPIPorSIT
    | SLIP
    | IPSecOrGRE
    | VLAN
    | JumboEthernet
    | Google
    | GIF
    | PPTP
    | Loopback
    | AX25RadioModem

    with 
        member x.ToString =
            match x with
            | EthernetOrModem -> "Ethernet or modem"
            | TunnelOrVPN -> "generic tunnel or VPN"
            | DSL -> "DSL"
            | IPIPorSIT -> "IPIP or SIT"
            | SLIP ->  "SLIP"
            | IPSecOrGRE -> "IPSec or GRE"
            | VLAN -> "VLAN"
            | JumboEthernet -> "jumbo Ethernet"
            | Google -> "Google"
            | GIF -> "GIF"
            | PPTP -> "PPTP" 
            | Loopback -> "loopback"
            | AX25RadioModem -> "AX.25 radio modem"
        static member Parse (str: string) : Link =
            match str with
            | LinkType.EthernetOrModem -> EthernetOrModem
            | LinkType.TunnelOrVPN -> TunnelOrVPN
            | LinkType.DSL -> DSL
            | LinkType.IPIPorSIT -> IPIPorSIT
            | LinkType.SLIP -> SLIP
            | LinkType.IPSecOrGRE -> IPSecOrGRE
            | LinkType.VLAN -> VLAN
            | LinkType.JumboEthernet -> JumboEthernet
            | LinkType.Google -> Google
            | LinkType.GIF -> GIF
            | LinkType.PPTP -> PPTP
            | LinkType.Loopback -> Loopback
            | LinkType.AX25RadioModem -> AX25RadioModem
