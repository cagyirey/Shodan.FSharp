# Shodan.FSharp [![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/4bjkrjqxcneubho9?svg=true)](https://ci.appveyor.com/project/cagyirey/shodan-fsharp) [![Travis Build Status](https://travis-ci.org/cagyirey/Shodan.FSharp.svg?branch=master)](https://travis-ci.org/cagyirey/Shodan.FSharp)

### Usage

```fsharp
open Shodan.FSharp

[<EntryPoint>]
let main argv = 
    // Acquire account info for the API key in config.yml
    let accountInfo = Shodan.AccountInfo() |> Async.RunSynchronously
    
    printfn "----- Account info -----\nUsername: %s\nCredits: %i\n\Date created: %s\n------------------------"
        accountInfo.DisplayName
        accountInfo.Credits
        (accountInfo.Created.ToString("dd/mm/yyyy"))
    0
```