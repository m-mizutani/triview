# triview

CLI tool to lookup [trivy database](https://github.com/aquasecurity/trivy-db/). Database can be downloaded from https://github.com/aquasecurity/trivy-db/releases.

## Setup

```
go install github.com/m-mizutani/triview@latest
```

## Usage

### Show advisory source list

```
$ triview -d /path/to/db adv
GitHub Security Advisory Composer
GitHub Security Advisory Maven
GitHub Security Advisory Npm
(snip)
```

### Show advisory list by a source

```
$ triview -d /path/to/db adv ruby-advisory-db
Arabic-Prawn
RedCloth
VladTheEnterprising
actionmailer
(snip)

```

### Show advisories of a package

```
$ triview -d /path/to/db adv ruby-advisory-db rake
CVE-2020-8130: {"PatchedVersions":["\u003e= 12.3.3"]}
```

### Show vulnerability info

```
$ triview -d /path/to/db vuln CVE-2020-8130 | jq
{
  "Title": "rake: OS Command Injection via egrep in Rake::FileList",
  "Description": "There is an OS command injection vulnerability in Ruby Rake < 12.3.3 in Rake::FileList when supplying a filename that begins with the pipe character `|`.",
  "Severity": "MEDIUM",
  "CweIDs": [
    "CWE-78"
  ],
  "VendorSeverity": {
    "amazon": 2,
    "ghsa-rubygems": 2,
    "nvd": 2,
    "redhat": 2,
    "ruby-advisory-db": 3,
    "ubuntu": 2
  },
  "CVSS": {
    "nvd": {
      "V2Vector": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
      "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
      "V2Score": 6.9,
      "V3Score": 6.4
    },
    "redhat": {
      "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
      "V3Score": 6.4
    }
  },
  "References": [
(snip)
```

## License

MIT License