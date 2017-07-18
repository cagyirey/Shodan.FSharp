namespace Shodan.FSharp

open System
open System.Net

module internal Http =

    [<AutoOpen>]
    module private Utils =

        let inline relativeUri (uri: Uri) (path2 : string) =
           Uri <| sprintf "%s/%s" (uri.AbsoluteUri.Trim('/')) (path2.TrimStart('/'))
 
        let inline (@@) path1 path2 = relativeUri path1 path2

    let private shodanBaseUri = Uri "https://api.shodan.io"

    let private shodanApi = shodanBaseUri @@ "/shodan"

    let accountInfo = shodanBaseUri @@ "/account/profile"

    let apiInfo = shodanBaseUri @@ "/api-info"

    module Search = 

        let info (ip : IPAddress) = shodanApi @@ (sprintf "/host/%O" ip)

        let search = shodanApi @@ "/host/search"

        let count = shodanApi @@ "/host/count"

        let ports = shodanApi @@ "/ports"

        let tokens = search @@ "/tokens"

    module Scan =
        
        let procotols = shodanApi @@ "/protocols"

        let scan = shodanApi @@ "/scan"

        let scanInternet = scan @@ "/internet"

        let scanId id = scan @@ id

    module Alert =
            
        let alert = shodanApi @@ "/alert"

        let create = alert

        let enumerate = alert @@ "/info"

        let delete id = alert @@ id
            
        let info id = alert @@ (sprintf "/%s/info" id)

    module Directory =
            
        let query = shodanApi @@ "/query"

        let search = query @@ "/search"

        let tags = query @@ "/tags"

    module DNS =

        let private dns = shodanBaseUri @@ "/dns"

        let resolve = dns @@ "/resolve"

        let reverse = dns @@ "/reverse"

    module Tools = 

        let private tools = shodanBaseUri @@ "/tools"

        let httpHeaders =  tools @@ "/httpheaders"

        let myIP = tools @@ "/myip"

    module Experimental =

        let private labs = shodanBaseUri @@ "/labs"

        let honeyscore (ip: IPAddress) = labs @@ sprintf "honeyscore/%O" ip
