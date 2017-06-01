namespace Shodan.FSharp

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
module LinkType = 

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
