#I @"packages/build/FAKE/tools"
#r @"FakeLib.dll"

open Fake
open Fake.AssemblyInfoFile
open Fake.ReleaseNotesHelper
open Fake.Testing

open System
open System.IO

type Project = 
    { Name: string
      Summary: string
      Guid: string }

let solutionName = "Shodan.FSharp"

let configuration = "Release"

let tags = "shodan"

let mainProject = 
    { Name = solutionName
      Summary = "A Shodan API client for F#."
      Guid = "cc90107d-7c65-4dcb-bc13-bb3e0d75933f" }

let releaseNotes = ReleaseNotesHelper.parseReleaseNotes (File.ReadLines "RELEASE_NOTES.md")

let solutionFile = solutionName + ".sln"

// publishable projects - for generated lib info
let projects = [ mainProject ]

let buildDir = "./bin"
let outputDir = buildDir @@ configuration
let testBuildDir = "./tests/bin"

let testAssemblies = "tests/bin/**/*Tests*.dll"

let isAppveyorBuild = (environVar >> isNotNullOrEmpty) "APPVEYOR" 
let appveyorBuildVersion = sprintf "%s-a%s" releaseNotes.AssemblyVersion (DateTime.UtcNow.ToString "yyMMddHHmm")

Target "Clean" (fun () ->
    CleanDirs [buildDir]
)

Target "AppveyorBuildVersion" (fun () ->
    Shell.Exec("appveyor", sprintf "UpdateBuild -Version \"%s\"" appveyorBuildVersion) |> ignore
)

Target "AssemblyInfo" (fun () ->
    List.iter(fun project -> 
        let filename = "./src" @@ project.Name @@ "AssemblyInfo.fs"
        CreateFSharpAssemblyInfo filename
            [ Attribute.Title project.Name
              Attribute.Product solutionName
              Attribute.Description project.Summary
              Attribute.Version releaseNotes.AssemblyVersion
              Attribute.FileVersion releaseNotes.AssemblyVersion
              Attribute.Guid project.Guid ]) projects
)

Target "CopyLicense" (fun _ ->
    [ "LICENSE.md" ]
    |> CopyTo (outputDir)
)

Target "Build" (fun _ ->
    !! solutionFile
    |> MSBuildRelease "" "Rebuild"
    |> ignore
)

Target "ILMerge" (fun _ -> 
    let ilmergePath = "./packages/build/ilmerge/tools/ilmerge.exe"
    let targetBinary = solutionName + ".dll"
    let mergeFolder = Directory.CreateDirectory (buildDir @@ "merged")
    ILMerge (fun p -> { p with ToolPath = ilmergePath }) (mergeFolder.FullName @@ targetBinary) (Path.GetFullPath <| outputDir @@ targetBinary)
)

Target "RunTests" (fun _ ->
    !! testAssemblies
    |> NUnit3 (fun p ->
        { p with
            WorkingDir = Path.GetFullPath (testBuildDir @@ configuration)
            ShadowCopy = false
            TimeOut = TimeSpan.FromMinutes 10. })
)

Target "All" DoNothing

"Clean"
    =?> ("AppveyorBuildVersion", isAppveyorBuild)
    ==> "AssemblyInfo"
    ==> "CopyLicense"
    ==> "Build"
    =?>("ILMerge", configuration = "Release")
    //==> "RunTests"
    ==> "All"

let target = getBuildParamOrDefault "target" "All"

RunTargetOrDefault target