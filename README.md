# Horizon Cloud next-gen powershell modules

This PowerShell module provides cmdlets for interacting with the Horizon Cloud next-gen API, simplifying common tasks such as management and data retrieval."

## Description

This module offers a streamlined way to manage Horizon Cloud next-gen through PowerShell. It includes cmdlets for:

*   Get the edge & uag status .
*   Retrieving pools & poolgroups information.
*   Retrieving user & groups details from IDP
*   Retrieving app volumes details
*   Retrieving Images details
*   Create new pool & poolgroup
*   Create entitlements
*   Create edge & uag
*   Management activities on the pools , poolgroups and etc

## Installation
Download the module github and install it manually:

Download the latest release ZIP file.
Unzip the contents to a module directory (e.g., $env:USERPROFILE\Documents\WindowsPowerShell\Modules\MyAwesomePowerShellModule).
Import the module:
<!-- end list -->

```powershell
Install-Module -Name Import-Module "hcs-nextgen.psm1" -Force
