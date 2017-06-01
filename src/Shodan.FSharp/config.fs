namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =
    open System.IO

    [<Literal>]
    let ConfigFile = "Shodan.resx"

    type Settings = ResXProvider<ConfigFile>