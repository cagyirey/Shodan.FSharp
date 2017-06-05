namespace Shodan.FSharp.Tests

open Shodan.FSharp

open FsUnit
open NUnit.Framework

[<TestFixture>]
module ``Creditless API tests`` =

    [<Test>]
    let ``Account is activated and has API credits`` () =
        let accountInfo = Shodan.AccountInfo () |> Async.RunSynchronously
        accountInfo.Member |> should equal true
        accountInfo.Credits |> should be (greaterThan 0)

    [<Test>]
    let ``API key has remaining credits`` () =
        let apiInfo = Shodan.ApiInfo () |> Async.RunSynchronously
        [apiInfo.QueryCredits; apiInfo.ScanCredits] |> Seq.iter (should be (greaterThan 0))