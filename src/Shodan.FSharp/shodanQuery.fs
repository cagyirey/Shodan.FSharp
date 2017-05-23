namespace Shodan.FSharp

open System
open System.Net

module Query = 

    let private dateString (date: DateTime) = date.ToString("dd/mm/yyyy")
    
    type GeoBounding =
        | Radius of float
        | Box of float * float

    let After (date: DateTime) = "after:" + dateString date

    let ASN name = "asn:" + name

    let Before (date: DateTime) = "before:" + dateString date

    let City city = "city:" + city

    let Geo (lat, long) bounding =
        match bounding with
        | Radius r -> sprintf "geo:%G%G%G" lat long r 
        | Box(l, r) -> sprintf "geo:%G%G%G%G" lat long l r

    let Hash hash = "hash:" + hash

    let HasIPv6 = "has_ipv6:true"

    let HasScreenshot = "has_screenshot:true"

    let HostnameContains substr = "hostname:" + substr

    let ISP isp = "isp:" + isp
    
    // let Link _ = what is this supposed to be?

    let Netblock (mask: IPAddress) block = sprintf "net:%O/%i" mask block

    let Org org = "org:" + org

    let OS os = "os:" + os

    let Port port = sprintf "port:%i" port

    let Postal postal = "postal:" + postal

    let Product prod = "product:" + prod

    let State state = "state:" + state
    
    let Version ver = "version:" + ver

    module Bitcoin = 

        let IP (ip: IPAddress) = sprintf "bitcoin.ip:%O" ip

        let IPCount count = sprintf "bitcoin.ip_count:%i" count

        let Port port = sprintf "bitcoin.port:%i" port

        let Version ver = "bitcoin.version:" + ver

    module Http =

        let Component cmp = "http.component:" + cmp