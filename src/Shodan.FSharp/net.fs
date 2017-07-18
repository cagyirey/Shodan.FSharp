namespace rec Shodan.FSharp

#nowarn "58"

open System
open System.Net
open FSharp.Data
open FSharp.Data.JsonExtensions

open Shodan.FSharp
open Shodan.FSharp.JsonResponse

open System
open System.Reflection
open System.Runtime.InteropServices

[<AutoOpen>]
module private Utils =

    let httpHeaders = 
        let version = string <| Assembly.GetExecutingAssembly().GetName().Version
        [HttpRequestHeaders.UserAgent (sprintf "Win32:Shodan.FSharp:%s" version)]

    let inline queryFromOptionalArgs (args : #seq<string * string option>) =
        Seq.choose(
            function 
            | name, Some facet -> Some(name, string facet)
            | _ -> None) args
        |> Seq.toList

type Shodan (apiKey: Security.SecureString) =

    member internal __.ApiRequest(apiEndpoint: Uri, query, ?httpMethod, ?httpBody: HttpRequestBody) =
        let md = defaultArg httpMethod HttpMethod.Get
        let key = Marshal.SecureStringToGlobalAllocUnicode apiKey

        async {
            try
                let! resp = 
                    match httpBody with
                    | None -> 
                        Http.AsyncRequest(
                            string apiEndpoint,
                            headers=httpHeaders,
                            query=("key", Marshal.PtrToStringUni key) :: query,
                            httpMethod=md,
                            silentHttpErrors=true)
                    | Some body -> 
                        Http.AsyncRequest(
                            string apiEndpoint,
                            headers=httpHeaders,
                            query=("key", Marshal.PtrToStringUni key) :: query,
                            body=body,
                            httpMethod=md,
                            silentHttpErrors=true)

                match resp.Body with
                | Text body when resp.StatusCode = 200 -> return body
                | Text err -> return raise (ShodanWebException err)

            finally
                Marshal.ZeroFreeGlobalAllocUnicode key
        }

    /// Returns information about the API plan belonging to the given API key.
    member x.ApiInfo () = 
        async {
            let! json = x.ApiRequest(Http.apiInfo, [])
            return ApiInfoJson.Parse json
        }

    /// Returns information about the Shodan account linked to this API key.
    member x.AccountInfo () = 
        async {
            let! json = x.ApiRequest(Http.accountInfo, [])
            return AccountInfoJson.Parse json
        }

    /// Get your current IP address as seen from the Internet.
    member x.MyIP () =
        async {
            let! ip = x.ApiRequest(Http.Tools.myIP, [])
            return ip.Trim('\"') |> IPAddress.Parse
        }

    /// Shows the HTTP headers that your client sends when connecting to a webserver.
    member x.HttpHeaders (headers) =
        async {
            let! headers = x.ApiRequest(Http.Tools.httpHeaders, [])
            return
                (JsonValue.Parse headers).Properties 
                |> Array.map (fun (k: string, v: JsonValue) -> k, v.AsString())
        }
    
    member x.Alerts = Alerts(x)
    
    member x.Directory = Directory(x)

    member x.DNS = DNS(x)
    
    member x.Experimental = Experimental(x)
    
    member x.Scan = Scan(x)
    
    member x.Search = Search(x)

    interface IDisposable with

        override __.Dispose () =
            apiKey.Dispose()

type Search internal (sho: Shodan) =

    /// Returns all services that have been found on the given host IP.
    member this.HostInfo(host: IPAddress, ?history: bool, ?minify: bool) = 
                async { 
                    let! json = sho.ApiRequest(Http.Search.info host, queryFromOptionalArgs [ "history", Option.map string history; "minify", Option.map string minify ])
                    return Search.HostInfoJson.Parse json
                }

    /// Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.
    member this.Search(query, ?facets: #seq<string>, ?page: int) =
        async { 
            let! json = 
                sho.ApiRequest(
                    Http.Search.search,
                    ("query", Query.QueryToString query) :: queryFromOptionalArgs ["facets", Option.map (String.concat ",") facets; "page", Option.map string page])
            return 
                ((JsonValue.Parse json)?matches).AsArray()
                |> Array.map Banner.makeBanner
        }
    /// This method behaves identical to `Shodan.Search` with the only difference that this method does not return any host results, it only returns the total number of results that matched the query and any facet information that was requested. As a result this method does not consume query credits.
    member this.Count(query, ?facets: #seq<string>, ?page: int) =
        async { 
            let! json = sho.ApiRequest(Http.Search.count, ("query", Query.QueryToString query) :: queryFromOptionalArgs ["facets", Option.map (String.concat ",") facets; "page", Option.map string page])
            return Search.CountJson.Parse json
        }

    /// This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.
    member this.Tokens(query) =
        async {
            let! json = sho.ApiRequest(Http.Search.tokens, ["query", Query.QueryToString query])
            return Search.TokensJson.Parse json
        }

    /// This method returns a list of port numbers that the crawlers are looking for.
    member this.Ports () =
        async {
            let! json = sho.ApiRequest(Http.Search.ports, [])
            return Search.PortsJson.Parse json
        }

type Scan internal (sho: Shodan) =
    
    /// This method returns an object containing all the protocols that can be used when launching an Internet scan.
    member this.Protocols () =
        async {
            let! json = sho.ApiRequest(Http.Scan.procotols, [])
            return Scan.ProtocolsJson.Parse json
        }

    /// Use this method to request Shodan to crawl a network.
    member this.Scan(targets: #seq<string>) =
        async {
            let! json = 
                sho.ApiRequest(
                    Http.Scan.scan,
                    [ "ips", String.concat "," targets ],
                    HttpMethod.Post)
            return Scan.ScanJson.Parse json
        }


        
    /// Use this method to request Shodan to crawl the Internet for a specific port.
    member this.Internet(port: int, protocol) =
        async {
            let! json = 
                sho.ApiRequest(
                    Http.Scan.scanInternet,
                    [ "port", string port
                      "protocol", protocol ],
                    HttpMethod.Post)
            return Scan.InternetJson.Parse json
        }

    /// Check the progress of a previously submitted scan request. Possible values for the status are: `SUBMITTING`, `QUEUE`, `PROCESSING, `DONE`
    member this.ScanStatus(scanId) =
        async {
            let! json = sho.ApiRequest(Http.Scan.scanId scanId, [])
            return Scan.ScanIdJson.Parse json
        }

type DNS internal (sho: Shodan) =

    /// Look up the IP address for the provided list of hostnames.
    member this.Resolve(hosts: #seq<string>) = 
        async {
            let! json = sho.ApiRequest(Http.DNS.resolve, ["hostnames", String.concat "," hosts])
            
            return 
                [| for (k, v) in (JsonValue.Parse json).Properties  do 
                    yield k, v.AsString() |> IPAddress.Parse |]
        }

    /// Look up the hostnames that have been defined for the given list of IP addresses.
    member this.Reverse(ips: #seq<IPAddress>) =
        async {
            let query = 
                Seq.map (fun (ip: IPAddress) -> string ip) ips
                |> String.concat ","

            let! json = sho.ApiRequest(Http.DNS.reverse, ["ips", query])
            
            return 
                [| for (k, v) in (JsonValue.Parse json).Properties do
                    yield IPAddress.Parse k, v.AsArray() |> Array.map(fun jsVal -> jsVal.AsString ()) |]
        }

type Alerts internal (sho: Shodan) =

    /// Returns the information about a specific network alert.
    member this.GetAlert(id) =
        async {
            let! json = sho.ApiRequest(Http.Alert.info id, [])
            return (Alert.AlertInfoJson.Parse json)
        }

    /// Returns a listing of all the network alerts that are currently active on the account.
    member this.EnumerateAlerts () =
        async {
            let! json = sho.ApiRequest(Http.Alert.enumerate, [])
            return Alert.EnumerateAlertsJson.Parse json
        }

    /// Use this method to create a network alert for a defined IP/ netblock which can be used to subscribe to changes/ events that are discovered within that range.
    member this.CreateAlert(alert) =
        async {
            do!
                sho.ApiRequest(Http.Alert.create, [], HttpMethod.Post, TextRequest alert)
                |> Async.Ignore
        }

    /// Remove the specified network alert.
    member this.DeleteAlert(id) =
        async {
            do!
                sho.ApiRequest(Http.Alert.delete id, [], HttpMethod.Delete)
                |> Async.Ignore
        }

type Directory internal (sho: Shodan) =

    /// Use this method to obtain a list of search queries that users have saved in Shodan.
    member this.Query(?page: int, ?sort : QuerySort, ?order: QueryOrder) =
        async {
            let! json = 
                sho.ApiRequest(
                    Http.Directory.query,
                    queryFromOptionalArgs 
                        ["page", Option.map string page
                         "sort", Option.map string sort
                         "order", Option.map string order])

            return Directory.QueryJson.Parse json
        }
    
    /// Use this method to search the directory of search queries that users have saved in Shodan.
    member this.Search(query, ?page: int) =
        async {
            let! json = 
                sho.ApiRequest(
                    Http.Directory.search,
                    ("query", query) ::
                    Option.fold(fun _ pg -> ["page", string pg]) [] page)
            return Directory.SearchJson.Parse json
        }

    /// Use this method to obtain a list of popular tags for the saved search queries in Shodan.
    member this.Tags(?size: int) =
        async {
            let! json =
                sho.ApiRequest(
                    Http.Directory.tags,
                    queryFromOptionalArgs [ "size", Option.map string size ])
            return Directory.TagsJson.Parse json
        }

type Experimental internal (sho: Shodan) =

    /// Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot).
    member this.Honeyscore(ip: IPAddress) =
        async {
            let! json = sho.ApiRequest(Http.Experimental.honeyscore ip, [])
            return (JsonValue.Parse json).AsFloat()
        }