namespace Shodan.FSharp

open System
open System.Net

module Query = 

    let private dateString (date: DateTime) = date.ToString("dd/MM/yyyy")

    /// Only show results that were collected after the given date (dd/mm/yyyy).
    let After (date: DateTime) = Facets.After, dateString date

    /// The Autonomous System Number that identifies the network the device is on.
    let ASN (name: string) = Facets.ASN, name

    /// Only show results that were collected before the given date (dd/mm/yyyy).
    let Before (date: DateTime) = Facets.Before, dateString date

    /// Show results that are located in the given city.
    let City (city: string) = Facets.City, city

    /// Filter by geographical 
    let Geo (lat, long) bounding = Facets.Geo, sprintf "%G,%G,%O" lat long bounding

    // Hash of the "data" property
    let Hash (hash: string) = Facets.Hash, hash

    /// Only show results that were discovered on IPv6.
    let HasIPv6 (ipv6: bool) = Facets.HasIPv6, string ipv6

    /// Only show results that have a screenshot available.
    let HasScreenshot (screenshots: bool) = Facets.HasScreenshots, string screenshots

    /// Search for hosts that contain the given value in their hostname.
    let Hostname (host: string) = Facets.Hostname, host

    /// Find devices based on the upstream owner of the IP netblock.
    let ISP (isp: string) = Facets.ISP, isp

    /// Find devices depending on their connection to the Internet.
    let Link (link: string) = Facets.Link, link

    /// Search by netblock using CIDR notation; ex: net:69.84.207.0/24
    let Netblock (mask: IPAddress) block = Facets.Netblock, sprintf "%O/%i" mask block

    /// Find devices based on the owner of the IP netblock.
    let Org (org: string) = Facets.Org, org

    /// Filter results based on the operating system of the device.
    let OS (os: string) = Facets.OS, os

    /// Find devices based on the services/ ports that are publicly exposed on the Internet.
    let Port (port: int) = Facets.Port, string port

    /// Search by postal code.
    let Postal (postal: string) = Facets.Postal, postal

    /// Filter using the name of the software/ product; ex: product:Apache
    let Product (prod: string) = Facets.Product, prod

    /// Search for devices based on the state/ region they are located in.
    let State (state: string) = Facets.State, state
    
    /// Filter the results to include only products of the given version; ex: product:apache version:1.3.37
    let Version (ver: string) = Facets.Version, ver

    module Bitcoin = 

        /// Find Bitcoin servers that had the given IP in their list of peers.
        let IP (ip: IPAddress) = Facets.Bitcoin.IP, string ip

        /// Find Bitcoin servers that return the given number of IPs in the list of peers.
        let IPCount (count: int) = Facets.Bitcoin.IPCount,  count

        /// Find Bitcoin servers that had IPs with the given port in their list of peers.
        let Port (port: int) = Facets.Bitcoin.Port, int port

        /// Filter results based on the Bitcoin protocol version.
        let Version (version: string) = Facets.Bitcoin.Version, version

    module Http =

        /// Name of web technology used on the website
        let Component (comp: string) = Facets.Http.Component, comp

        // TODO: use typed arguments
        /// Category of web components used on the website
        let ComponentCategory (category: string) = Facets.Http.ComponentCategory, category

        /// Search the HTML of the website for the given value.
        let Html (html: string) = Facets.Http.Html, html

        /// Hash of the website HTML
        let HtmlHash (hash: string) = Facets.Http.HtmlHash, hash

        /// Response status code
        let StatusCode (status: int) = Facets.Http.StatusCode, string status

        /// Search the title of the website
        let Title (title: string) = Facets.Http.Title, title

    module Ntp =

        /// Find NTP servers that had the given IP in their monlist.
        let IP (ip: IPAddress) = Facets.Ntp.IP, string ip

        /// Find NTP servers that return the given number of IPs in the initial monlist response.
        let IPCount (count: int) = Facets.Ntp.IPCount, string count

        /// Whether or not more IPs were available for the given NTP server.
        let More (hasMore: bool) = Facets.Ntp.More, string hasMore

        /// Find NTP servers that had IPs with the given port in their monlist.
        let Port (port: int) = Facets.Ntp.Port, string port

    module Ssl =
        
        /// Search all SSL data
        let Ssl (query: string) = Facets.Ssl.Ssl, query

        /// Application layer protocols such as HTTP/2 ("h2")
        let Applicationlayer (alpn: string) = Facets.Ssl.Applicationlayer, alpn

        /// Number of certificates in the chain
        let ChainCount (count: int) = Facets.Ssl.ChainCount, string count

        /// Possible values: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
        let Version (version: string) = Facets.Ssl.Version, version

        // TODO: use typed arguments
        /// Certificate algorithm
        let CertAlgorithm (alg: string) = Facets.Ssl.CertAlgorithm, alg

        /// Whether the SSL certificate is expired or not
        let CertExpired (expired: bool) = Facets.Ssl.CertExpired, string expired

        /// Names of extensions in the certificate
        let CertExtension ext = Facets.Ssl.CertExtensions, ext

        // TODO: use typed arguments
        /// Serial number as an integer or hexadecimal string
        let CertSerial serial = Facets.Ssl.CertSerial, serial

        /// Number of bits in the public key
        let PublicKeyBits (bits: int) = Facets.Ssl.PublicKeyBits, string bits

        /// Public key type
        let PublicKeyType keyType = Facets.Ssl.PublicKeyType, keyType

        /// SSL version of the preferred cipher
        let CipherVersion version = Facets.Ssl.Version, version

        /// Number of bits in the preferred cipher
        let CipherBits (bits: int) = Facets.Ssl.CipherBits, string bits

        /// Name of the preferred cipher
        let Cipher name = Facets.Ssl.Cipher, name

    module Telnet = 
        
        /// Search all the options
        let Options (opts: #seq<string>) = Facets.Telnet.Options, String.concat "," opts

        /// The server requests the client to support these options
        let Do (doOpts: #seq<string>)  = Facets.Telnet.Do, String.concat "," doOpts

        /// The server requests the client to not support these options
        let Dont (dontOpts: #seq<string>) = Facets.Telnet.Dont, String.concat "," dontOpts

        /// The server supports these options
        let Will (willOpts: #seq<string>) = Facets.Telnet.Will, String.concat "," willOpts

        /// The server doesnt support these options
        let Wont (wontOpts: #seq<string>) = Facets.Telnet.Wont, String.concat "," wontOpts
