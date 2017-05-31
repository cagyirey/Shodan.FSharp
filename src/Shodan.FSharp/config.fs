namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =
    open System.IO

    [<Literal>]
    let ConfigFile = __SOURCE_DIRECTORY__ + "/shodan.resx"

    type Settings = ResXProvider<ConfigFile>