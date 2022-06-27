rule unknown_threat
{
meta:
        Author = "@funbird"
        Description = "the rule detect the presence of SSH-one, remotesec, darklord excutable file"
strings:
     $domain = "darkl0rd.com:7758"
     $remotesec = "remotesec: 56565"
     $rc = "rc.local"
    $notes = "notes.txt"
     $examples = "examples.desktop"

condition:
     $domain and $remotesec and $rc and $notes and $examples
}
