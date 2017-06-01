namespace Shodan.FSharp

#nowarn "58"

open System
open System.Net
open FSharp.Data

open Shodan.FSharp.Configuration     
open Shodan.FSharp
open Shodan.FSharp.JsonResponse
open System.Reflection

exception ShodanError of string

[<AutoOpen>]
module private Utils = 

    let httpHeaders = 
        let version = string <| Assembly.GetExecutingAssembly().GetName().Version
        [HttpRequestHeaders.UserAgent (sprintf "Win32:Shodan.FSharp:%s" version)]

    let inline makeFacetQuery (query) =
        List.map (fun (k, v) -> sprintf "%s:%s" k v) query
        |> String.concat " "

    let inline queryFromOptionalArgs (args : #seq<string * ^T option>) =
        Seq.choose(
            function 
            | name, Some facet -> Some(name, string facet)
            | _ -> None) args
        |> Seq.toList

type Shodan private () =

    static member internal ApiRequest(apiEndpoint: Uri, query, ?httpMethod, ?httpBody: HttpRequestBody) =
        let md = defaultArg httpMethod HttpMethod.Get
        async {
            let! resp = 
                match httpBody with
                | None -> 
                    Http.AsyncRequest(
                        string apiEndpoint,
                        headers=httpHeaders,
                        query=("key", Settings.SecretKey) :: query,
                        httpMethod=md)
                | Some body -> 
                    Http.AsyncRequest(
                        string apiEndpoint,
                        headers=httpHeaders,
                        query=("key", Settings.SecretKey) :: query,
                        body=body,
                        httpMethod=md)
            match resp.Body with
            | Text body  when resp.StatusCode = 200 -> return body
            | Text err -> return raise (ShodanError (ErrorJson.Parse err).Error)
        }

    /// Returns information about the API plan belonging to the given API key.
    static member ApiInfo () = 
        async {
            let! json = Shodan.ApiRequest(WebApi.apiInfo, [])
            return ApiInfoJson.Parse json
        }

    /// Returns information about the Shodan account linked to this API key.
    static member AccountInfo () = 
        async {
            let! json = Shodan.ApiRequest(WebApi.accountInfo, [])
            return AccountInfoJson.Parse json
        }

    /// Get your current IP address as seen from the Internet.
    static member MyIP () =
        async {
            let! ip = Shodan.ApiRequest(WebApi.Tools.myIP, [])
            return ip.Trim('\"') |> IPAddress.Parse
        }

    /// Shows the HTTP headers that your client sends when connecting to a webserver.
    static member HttpHeaders (headers) =
        async {
            let! headers = Shodan.ApiRequest(WebApi.Tools.httpHeaders, [])
            return
                (JsonValue.Parse headers).Properties ()
                |> Array.map (fun (k: string, v: JsonValue) -> k, v.AsString())
        }

type Search private () =

    /// Returns all services that have been found on the given host IP.
    static member HostInfo(host: IPAddress, ?history: bool, ?minify: bool) = 
        async { 
            let! json = Shodan.ApiRequest(WebApi.Search.info host, queryFromOptionalArgs [ "history", history; "minify", minify ])
            return Search.HostInfoJson.Parse json
        }

    /// Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.
    static member Search(query, ?facets: #seq<string>, ?page: int) =
        async { 
            let! json = 
                Shodan.ApiRequest(
                    WebApi.Search.search,
                    ("query", makeFacetQuery query) :: queryFromOptionalArgs ["facets", Option.map (String.concat ",") facets; "page", Option.map string page])
            return Search.SearchJson.Parse json
        }

    /// This method behaves identical to `Shodan.Search` with the only difference that this method does not return any host results, it only returns the total number of results that matched the query and any facet information that was requested. As a result this method does not consume query credits.
    static member Count(query, ?facets: #seq<string>, ?page: int) =
        async { 
            let! json = Shodan.ApiRequest(WebApi.Search.count, ("query", makeFacetQuery query) :: queryFromOptionalArgs ["facets", Option.map (String.concat ",") facets; "page", Option.map string page])
            return Search.CountJson.Parse json
        }

    /// This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.
    static member Tokens(query) =
        async {
            let! json = Shodan.ApiRequest(WebApi.Search.tokens, ["query", makeFacetQuery query])
            return Search.TokensJson.Parse json
        }

    /// This method returns a list of port numbers that the crawlers are looking for.
    static member Ports () =
        async {
            let! json = Shodan.ApiRequest(WebApi.Search.ports, [])
            return Search.PortsJson.Parse json
        }

type Scan private () =
    
    /// This method returns an object containing all the protocols that can be used when launching an Internet scan.
    static member Protocols () =
        async {
            let! json = Shodan.ApiRequest(WebApi.Scan.procotols, [])
            return Scan.ProtocolsJson.Parse json
        }

    /// Use this method to request Shodan to crawl a network.
    static member Scan(targets: #seq<string>) =
        async {
            let! json = 
                Shodan.ApiRequest(
                    WebApi.Scan.scan,
                    [ "ips", String.concat "," targets ],
                    HttpMethod.Post)
            return Scan.ScanJson.Parse json
        }
        
    /// Use this method to request Shodan to crawl the Internet for a specific port.
    static member Internet(port: int, protocol) =
        async {
            let! json = 
                Shodan.ApiRequest(
                    WebApi.Scan.scanInternet,
                    [ "port", string port
                      "protocol", protocol ],
                    HttpMethod.Post)
            return Scan.InternetJson.Parse json
        }

    /// Check the progress of a previously submitted scan request. Possible values for the status are: `SUBMITTING`, `QUEUE`, `PROCESSING, `DONE`
    static member ScanStatus(scanId) =
        async {
            let! json = Shodan.ApiRequest(WebApi.Scan.scanId scanId, [])
            return Scan.ScanIdJson.Parse json
        }

type DNS private () =

    /// Look up the IP address for the provided list of hostnames.
    static member Resolve(hosts) = 
        async {
            let! json = Shodan.ApiRequest(WebApi.DNS.resolve, ["hostnames", String.concat "," hosts])
            return DNS.ResolveJson.Parse json
        }

    /// Look up the hostnames that have been defined for the given list of IP addresses.
    static member Reverse(ips) =
        async {
            let query = 
                Seq.map (fun (ip: IPAddress) -> string ip) ips
                |> String.concat ","

            let! json = Shodan.ApiRequest(WebApi.DNS.reverse, ["ips", query])
            return DNS.ReverseJson.Parse json
        }

type Alerts private () =

    /// Returns the information about a specific network alert.
    static member GetAlert(id) =
        async {
            let! json = Shodan.ApiRequest(WebApi.Alert.info id, [])
            return Alert.AlertInfoJson.Parse json
        }

    /// Returns a listing of all the network alerts that are currently active on the account.
    static member EnumerateAlerts () =
        async {
            let! json = Shodan.ApiRequest(WebApi.Alert.enumerate, [])
            return Alert.EnumerateAlertsJson.Parse json
        }

    /// Use this method to create a network alert for a defined IP/ netblock which can be used to subscribe to changes/ events that are discovered within that range.
    static member CreateAlert(alert) =
        async {
            do!
                Shodan.ApiRequest(WebApi.Alert.create, [], HttpMethod.Post, TextRequest alert)
                |> Async.Ignore
        }

    /// Remove the specified network alert.
    static member DeleteAlert(id) =
        async {
            do!
                Shodan.ApiRequest(WebApi.Alert.delete id, [], HttpMethod.Delete)
                |> Async.Ignore
        }

type Directory private () =

    /// Use this method to obtain a list of search queries that users have saved in Shodan.
    static member Query(?page: int, ?sort : QuerySort, ?order: QueryOrder) =
        async {

            let! json = 
                Shodan.ApiRequest(
                    WebApi.Directory.query,
                    queryFromOptionalArgs 
                        ["page", Option.map string page
                         "sort", Option.map string sort
                         "order", Option.map string order])

            return Directory.QueryJson.Parse json
        }
    
    /// Use this method to search the directory of search queries that users have saved in Shodan.
    static member Search(query, ?page) =
        async {
            let! json = 
                Shodan.ApiRequest(
                    WebApi.Directory.search,
                    ("query", query) ::
                    Option.fold(fun _ pg -> pg) [] page)
            return Directory.SearchJson.Parse json
        }

    /// Use this method to obtain a list of popular tags for the saved search queries in Shodan.
    static member Tags(?size: int) =
        async {
            let! json =
                Shodan.ApiRequest(
                    WebApi.Directory.tags,
                    queryFromOptionalArgs [ "size", Option.map string size ])
            return Directory.TagsJson.Parse json
        }

type Experimental private () =

    /// Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot).
    static member Honeyscore(ip: IPAddress) =
        async {
            let! json = Shodan.ApiRequest(WebApi.Experimental.honeyscore ip, [])
            return (JsonValue.Parse json).AsFloat()
        }