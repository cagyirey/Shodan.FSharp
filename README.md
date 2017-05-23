### Shodan.FSharp


## Usage

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