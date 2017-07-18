# Shodan.FSharp [![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/4bjkrjqxcneubho9?svg=true)](https://ci.appveyor.com/project/cagyirey/shodan-fsharp) [![Travis Build Status](https://travis-ci.org/cagyirey/Shodan.FSharp.svg?branch=master)](https://travis-ci.org/cagyirey/Shodan.FSharp)

### Installation

Open `Shodan.resx` and fill the `SecretKey` field with your Shodan.io API key. In the current stage, this information is compiled as plaintext into the output binary so it is recommended to avoid leaving important keys on the filesystem. Run `build.sh` or `build.cmd`.

### Dependencies

* [FSharp.Data](https://fsharp.github.io/FSharp.Data/index.html)

### Usage

The following snippet displays the account details for the API key, then dumps detailed information about the first 100 hosts returned by a search query.

```fsharp
open System.Net

open Shodan.FSharp

let apiCredentials = NetworkCredential("", "##ApiKey##")

let shodan = new Shodan(apiCredentials.SecurePassword)
let accountInfo = shodan.AccountInfo() |> Async.RunSynchronously

printfn "----- Account info -----\nUsername: %s\nCredits: %i\nDate created: %s\n------------------------"
    accountInfo.DisplayName
    accountInfo.Credits
    (accountInfo.Created.ToString("dd/MM/yyyy"))

let searchQuery = [
    Query.OS "Linux 2.6.x"
]
    
let results = 
    shodan.Search.Search searchQuery
    |> Async.RunSynchronously
    
printfn "First %i hosts returned for the search query \"%s\":\r\n\r\n%A"
    results.Length
    (Query.QueryToString searchQuery)
    results
```