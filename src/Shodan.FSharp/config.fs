namespace Shodan.FSharp

open System
open FSharp.Configuration

module Configuration =
    open System.IO

    type Config = YamlConfig<"config.yml">

    let Settings = Config()

    let cwd = (DirectoryInfo Environment.CurrentDirectory) in

    let cfgFile =
        match List.ofArray <| Environment.GetCommandLineArgs().[1..] with 
        | [] -> cwd.GetFiles("*.yml") |> Seq.tryHead
        | [cfgPath] ->
            let fInfo = FileInfo cfgPath
            if fInfo.Exists then Some fInfo else None

    let settingsInst = Settings.Load cfgFile.Value.FullName