### 0.0.1 - May 23 2017
* Initial release

### 0.0.2 - May 24 2017

* Fixes to API key configuration

### 0.0.3 - May 24 2017

* Use an embedded `.resx` file for configuration
* Use ILMerge

### 0.1.0 - May 26 2017

* Fixes to geolocation filtering
* Expanded API
* Added documentation

### 0.1.1 - May 28 2017

* Added network alert and search query web APIs

### 0.1.2 - May 31 2017

* Better type modeling for search queries

### 0.1.3 - June 1 2017
* Fix: `/tools/` web APIs point to the correct APIs
* Fix: URI concatenation works
* Added: more type modeling to web APIs

### 0.1.4 - June 4 2017

* Added typed queries for telnet options
* Changed the result type of DNS queries
* Forward non-200 HTTP statuses through 'ShodanException'

### 0.2.0 - June 5 2017

* Change the web API types to instance classes taking a `SecureString` API key
* Module `WebApi` changed to `Http`
* `ShodanError` changed to `ShodanWebException`
* Remove ILMerge

### 0.3.0 - July 18 2017
* Changed the banner type returned by search queries
* Use .NET 4.5