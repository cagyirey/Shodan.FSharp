# Shodan.FSharp [![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/4bjkrjqxcneubho9?svg=true)](https://ci.appveyor.com/project/cagyirey/shodan-fsharp) [![Travis Build Status](https://travis-ci.org/cagyirey/Shodan.FSharp.svg?branch=master)](https://travis-ci.org/cagyirey/Shodan.FSharp)

### Installation

Open `Shodan.resx` and fill the `SecretKey` field with your Shodan.io API key. In the current stage, this information is compiled as plaintext into the output binary so it is recommended to avoid leaving important keys on the filesystem. Run `build.sh` or `build.cmd`.

### Dependencies

* [FSharp.Data](https://fsharp.github.io/FSharp.Data/index.html)

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
        (accountInfo.Created.ToString("dd/MM/yyyy"))
    0
```