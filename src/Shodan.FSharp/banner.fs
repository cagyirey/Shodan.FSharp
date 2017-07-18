namespace Shodan.FSharp

open FSharp.Data.JsonExtensions
open FSharp.Data
open System.Net
open System

type Transport =
| Tcp
| Udp

type Location = {
    City: string
    CountryCode: string
    CountryCode3: string
    Country: string
    Latitude: double
    Longitude: double
    PostalCode: string
    RegionCode: string option
    
    AreaCode: Nullable<int>
    DmaCode: Nullable<int>
}

type Banner = {
    Hash: int
    Data: string
    // `ip` and `ip_str` or `ipv6`
    IPAddress: IPAddress
    Port: int
    Timestamp: DateTime
    Hostnames: string []
    Domains: string []    
    Org: string
    ISP: string
    Transport: Transport
    Location: Location 
    
    // Not marked as optional
    ASN: string option

    // Not marked as optional - nullable
    OS: string
    
    // Optional Properties
    Ssl: JsonValue option
    Opts: JsonValue option
    Uptime: TimeSpan option
    Link: Link option
    Title: string option
    Html: string option
    Product: string option
    Version: string option
    DeviceType: string option
    Info: string option
    CPE: string [] option
}

module Banner = 

    let inline private optionalInt (jsonObject: JsonValue) prop =
        jsonObject.TryGetProperty prop
        |> Option.map(JsonExtensions.AsInteger)

    let inline private optionalString (jsonObject: JsonValue) prop =
        jsonObject.TryGetProperty prop
        |> Option.map(JsonExtensions.AsString)

    let inline private optionalFloat (jsonObject: JsonValue) prop =
        jsonObject.TryGetProperty prop
        |> Option.map(JsonExtensions.AsFloat)

    let inline private optionalArray (jsonObject: JsonValue) prop =
        jsonObject.TryGetProperty prop
        |> Option.map(JsonExtensions.AsArray)

    let inline private nullableInt (jsonObject: JsonValue) prop =
        match jsonObject.GetProperty prop with
        | JsonValue.Null -> Nullable() 
        | value -> Nullable(value.AsInteger())

    let makeLocation (jsonObject: JsonValue) =  {
        City = (jsonObject?city).AsString ()
        AreaCode = nullableInt jsonObject "area_code"
        CountryCode = (jsonObject?country_code).AsString ()
        CountryCode3 = (jsonObject?country_code3).AsString ()
        Country = (jsonObject?country_name).AsString ()
        Latitude = (jsonObject?latitude).AsFloat ()
        Longitude = (jsonObject?longitude).AsFloat ()
        PostalCode = (jsonObject?postal_code).AsString ()
        DmaCode = nullableInt jsonObject "dma_code"
        RegionCode = optionalString jsonObject "region_code"
    }

    let makeBanner (jsonObject: JsonValue) = 
        let ipAddress =
            match jsonObject.TryGetProperty "ip" with
            | Some ipAddr -> IPAddress(ipAddr.AsInteger64())
            | None -> IPAddress.Parse ((jsonObject?ipv6).AsString())
        {
            Hash = (jsonObject?hash).AsInteger ()
            ASN = optionalString jsonObject "asn"
            Data = (jsonObject?data).AsString ()
            IPAddress = ipAddress
            Port = (jsonObject?port).AsInteger ()
            Timestamp = (jsonObject?timestamp).AsDateTime()
            Hostnames = (jsonObject?hostnames).AsArray () |> Array.map (JsonExtensions.AsString)
            Domains = (jsonObject?domains).AsArray () |> Array.map (JsonExtensions.AsString)
            Location = makeLocation (jsonObject?location)
            Org = (jsonObject?org).AsString ()
            ISP = (jsonObject?isp).AsString ()
            Opts = (jsonObject.TryGetProperty "opts")
            Transport = match (jsonObject?transport).AsString () with "tcp" -> Tcp | "udp" -> Udp
            Ssl = jsonObject.TryGetProperty "ssl"
            OS = (jsonObject?os).AsString ()
            Uptime = (optionalFloat jsonObject "uptime") |> Option.map (TimeSpan.FromMinutes)
            Link = optionalString jsonObject "link" |> Option.map Link.Parse
            Title = optionalString jsonObject "title"
            Html = optionalString jsonObject "html"
            Product = optionalString jsonObject "product"
            Version = optionalString jsonObject "version"
            DeviceType = optionalString jsonObject "devicetype"
            Info = optionalString jsonObject "info"
            CPE = optionalArray jsonObject "cpe" |> Option.map(Array.map (JsonExtensions.AsString))
        }

