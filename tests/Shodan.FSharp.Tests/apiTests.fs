namespace Shodan.FSharp

open Shodan.FSharp

open FsUnit
open NUnit.Framework

open System.Security
open System.Net

[<CompilationRepresentationAttribute(CompilationRepresentationFlags.ModuleSuffix)>]
module Tests = 

    let sho = new Shodan(NetworkCredential("", "##ApiKey##").SecurePassword)

    [<TestFixture>]
    module ``Creditless API tests`` =
    
        [<Test>]
        let ``API key is activated and has API credits`` () =
            let accountInfo = sho.AccountInfo () |> Async.RunSynchronously
            accountInfo.Member |> should equal true
            accountInfo.Credits |> should be (greaterThan 0)

        [<Test>]
        let ``API key has remaining credits`` () =
            let apiInfo = sho.ApiInfo () |> Async.RunSynchronously
            [apiInfo.QueryCredits; apiInfo.ScanCredits] |> Seq.iter (should be (greaterThan 0))

    [<TestFixture>]
    module `` API Credit tests`` =
        
        let searchQuery = [
            Query.OS "Linux 2.6.x"
            Query.Port 23
        ]
        
        [<Test>]
        let ``Can retrieve search facets`` () = 
            let facets = sho.Search.Tokens(searchQuery) |> Async.RunSynchronously

            facets.Filters