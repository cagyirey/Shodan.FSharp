namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =
    open System.IO

    [<Literal>]
    let ConfigFile = "shodan.yml"

    type Settings = ResXProvider<"shodan.resx">