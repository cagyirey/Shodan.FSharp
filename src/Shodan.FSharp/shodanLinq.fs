namespace Shodan.FSharp

open System
open System.Collections.Generic
open System.Net
open System.Linq

open Shodan.FSharp
open Shodan.FSharp.JsonResponse

open Microsoft.FSharp.Linq
open Microsoft.FSharp.Quotations

module Linq =

    [<AutoOpen>]
    module Query =

        type QueryOptions = Dictionary<string, string>

        type BitcoinQuery = {
            IP: IPAddress
            IPCount: int
            Port: int
            Version: string
        }

        type HttpQuery = {
            Component: string
            ComponentCategory: string
            Html: string
            HtmlHash: string
            StatusCode: int
            Title: string
        }

        type TelnetQuery = {
            Options: string
            Do: string 
            Dont: string
            Will: string
            Wont: string
        }

        type NtpQuery = {
            IP: IPAddress
            IPCount: int
            More: bool
            Port: int
        }
        
        type SslCertQuery = {
            Algorithm: string
            Expired: bool
            Extensions: string
            Serial: string
            PublicKeyBits: int
            PublicKeyType: string
        }

        type SslQuery = {
            Ssl: string
            ApplicationLayer: string
            ChainCount: int
            Version: string
            Cert: SslCertQuery
            CipherVersion: string
            CipherBits: int
            Cipher: string
        }

        type ShodanQuery = {
            After: DateTime
            ASN: string
            Before: DateTime
            City: string
            Country: string
            Geo: GeoBounding
            Hash: string
            HasIPv6: bool
            HasScreenshots: bool
            Hostname: string
            ISP: string
            Netblock: string
            Org: string
            OS: string
            Port: int
            Postal: string
            Product: string
            State: string
            Version: string
            Bitcoin: BitcoinQuery
            Ssl: SslQuery
            Telnet: TelnetQuery
            Ntp: NtpQuery
        }

    type SearchResult = Search.SearchJson.Match

    let searchObj = Unchecked.defaultof<ShodanQuery>


    type Shodan.FSharp.Shodan with
        static member Hosts = 
    
    type ShodanSearchBuilder() = 

        /// 
        member __.Expression (e: Expr<_>) : IDictionary<string, string> = dict []

        member __.For(, f:ShodanQuery -> ShodanQuery) = searchObj
        
        member __.Yield(result) = ()

        member __.Zero () : ShodanQuery = searchObj

        [<CustomOperation("where", MaintainsVariableSpace=true)>]
        member __.Where(source: ShodanQuery, [<ProjectionParameter>] f:ShodanQuery -> bool) : ShodanQuery =
            source

        [<CustomOperation("select")>]
        member __.Select(source: ShodanQuery) = 
            

    let shodan = ShodanSearchBuilder()

    

    let result =
        shodan {
            for (host: ShodanQuery) in () do
                where(host.OS = "WinXP")
                select(host.OS, host.ISP)
        }