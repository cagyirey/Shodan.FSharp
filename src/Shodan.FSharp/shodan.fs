namespace Shodan.FSharp

type QueryOrder =
    | Ascending
    | Descending
    with 
        member x.ToString() = function
        | Ascending -> "asc"
        | Descending -> "desc"

type QuerySort =
    | Votes
    | Timestamp
    
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

type GeoBounding =
    | Radius of float
    | Box of float * float
    with 
    member x.ToString() = 
        match x with
        | Radius r -> sprintf "%G" r 
        | Box(l, r) -> sprintf "%G,%G" l r