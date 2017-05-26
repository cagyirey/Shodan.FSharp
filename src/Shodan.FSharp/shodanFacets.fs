namespace Shodan.FSharp

module Facets =

    [<Literal>]
    let After = "after"
    
    [<Literal>]
    let ASN = "asn"
    
    [<Literal>]
    let Before = "before"
    
    [<Literal>]
    let City = "city"
    
    [<Literal>]
    let Geo = "geo"
    
    [<Literal>]
    let Hash = "hash"

    [<Literal>]
    let HasIPv6 = "has_ipv6"

    [<Literal>]
    let HasScreenshots = "has_screenshots"

    [<Literal>]
    let Hostname = "hostname"

    [<Literal>]
    let ISP = "isp"

    [<Literal>]
    let Link = "link"

    [<Literal>]
    let Netblock = "net"

    [<Literal>]
    let Org = "org"

    [<Literal>]
    let OS = "os"

    [<Literal>]
    let Port = "port"

    [<Literal>]
    let Postal = "postal"

    [<Literal>]
    let Product = "product"

    [<Literal>]
    let State = "state"

    [<Literal>]
    let Version = "version"

    module Bitcoin =

        [<Literal>]
        let IP = "bitcoin.ip"

        [<Literal>]
        let IPCount = "bitcoin.ip_count"

        [<Literal>]
        let Port = "bitcoin.port"

        [<Literal>]
        let Version = "bitcoin.version"

    module Http = 

        [<Literal>]
        let Component = "http.component"

        [<Literal>]
        let ComponentCategory = "http.component_category"

        [<Literal>]
        let Html = "http.html"

        [<Literal>]
        let HtmlHash = "http.html_hash"

        [<Literal>]
        let StatusCode = "http.status"

        [<Literal>]
        let Title = "http.title"

    module Ntp =
    
        [<Literal>]
        let IP = "ntp.ip"
        
        [<Literal>]
        let IPCount = "ntp.ip_count"
        
        [<Literal>]
        let More = "ntp.more"
        
        [<Literal>]
        let Port = "ntp.port"

    module Telnet =
        
        [<Literal>]
        let Options = "telnet.option"
        
        [<Literal>]
        let Do = "telnet.do"
        
        [<Literal>]
        let Dont = "telnet.dont"
        
        [<Literal>]
        let Will = "telnet.will"
        
        [<Literal>]
        let Wont = "telnet.wont"

    module Ssl =
        
        [<Literal>]
        let Ssl = "ssl"
        
        [<Literal>]
        let Applicationlayer = "ssl.alpn"
        
        [<Literal>]
        let ChainCount = "ssl.chain_count"
        
        [<Literal>]
        let Version = "ssl.version"
        
        [<Literal>]
        let CertAlgorithm = "ssl.cert.alg"
        
        [<Literal>]
        let CertExpired = "ssl.cert.expired"

        [<Literal>]
        let CertExtensions = "ssl.cert.extension"
        
        [<Literal>]
        let CertSerial = "ssl.cert.serial"
        
        [<Literal>]
        let PublicKeyBits = "ssl.cert.pubkey.bits"
        
        [<Literal>]
        let PublicKeyType = "ssl.cert.pubkey.type"
        
        [<Literal>]
        let CipherVersion = "ssl.cipher.version"
        
        [<Literal>]
        let CipherBits = "ssl.cipher.bits"
        
        [<Literal>]
        let Cipher = "ssl.cipher.name"
