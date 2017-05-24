namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =
    open System.IO

    [<Literal>]
    let ConfigFile = "shodan.yml"

    type Config = YamlConfig<ConfigFile>

    let Settings = Config()
    
    let private cfgFile = Settings.LoadAndWatch ConfigFile