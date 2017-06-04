namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =

    [<Literal>]
    let ConfigFile = "Shodan.resx"

    type Settings = ResXProvider<ConfigFile>