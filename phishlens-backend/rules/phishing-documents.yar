/*
    Documents, shortcuts and the containers used to carry them.

    The through-line is that none of these files are what the person thinks they
    are opening. A shortcut is not a document. An RTF that loads an object from
    the network is not a letter. A disk image attached to an email exists to
    carry something across the boundary where Windows would otherwise have
    marked it as downloaded.
*/

rule LNK_Shortcut_Running_A_Shell
{
    meta:
        description = "A Windows shortcut that runs a command interpreter"
        rationale = "A shortcut attached to an email is not a document. Its target is a program and its arguments, and they are not shown to the person clicking it."
        severity = "HIGH"
        decisive = true
        technique = "T1204.001"

    strings:
        $powershell = "powershell" nocase wide ascii
        $cmd = "cmd.exe" nocase wide ascii
        $mshta = "mshta" nocase wide ascii
        $wscript = "wscript" nocase wide ascii
        $rundll = "rundll32" nocase wide ascii
        $curl = "curl " nocase wide ascii

    condition:
        // The shortcut header: a fixed 0x4C length followed by its class id.
        uint32(0) == 0x0000004C
        and any of them
}

rule Encoded_PowerShell_Command
{
    meta:
        description = "A base64-encoded PowerShell command line"
        rationale = "The encoding exists so the command cannot be read by whatever is looking at it, including the person. Legitimate automation has no reason to hide its arguments."
        severity = "HIGH"
        decisive = true
        technique = "T1027"

    strings:
        $enc1 = "-EncodedCommand" nocase wide ascii
        $enc2 = "-enc " nocase wide ascii
        $enc3 = "-e JAB" wide ascii
        $hidden = "-WindowStyle Hidden" nocase wide ascii
        $hidden2 = "-w hidden" nocase wide ascii
        $bypass = "-ExecutionPolicy Bypass" nocase wide ascii
        $nop = "-nop" nocase wide ascii

    condition:
        any of ($enc*) or (2 of ($hidden, $hidden2, $bypass, $nop))
}

rule RTF_Loading_Remote_Object
{
    meta:
        description = "An RTF document that pulls in an object from elsewhere when opened"
        rationale = "The document arrives carrying nothing detectable and fetches the rest of itself on open, so what was scanned is not what runs."
        severity = "HIGH"
        decisive = true

    strings:
        $rtf = "{\\rt"
        $objdata = "objdata" nocase
        $objautlink = "objautlink" nocase
        $objupdate = "\\objupdate" nocase
        $http = "http" nocase

    condition:
        $rtf at 0 and $objdata and ($objautlink or $objupdate) and $http
}

rule Office_DDE_Auto_Execution
{
    meta:
        description = "An Office document using a field to run an external command"
        rationale = "This runs a program without containing a macro, so a document that reports no macros can still start one."
        severity = "HIGH"
        decisive = true

    strings:
        $dde1 = "DDEAUTO" nocase
        $dde2 = "dde " nocase
        $field = "\\fldinst" nocase
        $shell1 = "powershell" nocase
        $shell2 = "cmd.exe" nocase
        $shell3 = "mshta" nocase

    condition:
        (any of ($dde*) or $field) and any of ($shell*)
}

rule Disk_Image_Attachment
{
    meta:
        description = "A disk image sent as an attachment"
        rationale = "Files taken out of a mounted image do not inherit the marking that tells Windows they came from the internet, so the warning that would normally appear does not."
        severity = "MEDIUM"
        technique = "T1553.005"

    strings:
        $iso = "CD001"
        $udf = "NSR02"
        $udf3 = "NSR03"

    condition:
        // The ISO 9660 descriptor sits at a fixed offset in the first sector set.
        $iso at 32769 or $udf at 32769 or $udf3 at 32769
}

rule Archive_Password_Hint_In_Message
{
    meta:
        description = "An encrypted archive whose password is supplied alongside it"
        rationale = "The encryption is not protecting anything from the recipient - they are given the key. It exists so that whatever scans the mail cannot open the file."
        severity = "MEDIUM"

    strings:
        $zip = { 50 4B 03 04 }
        $rar = "Rar!"
        $sevenzip = { 37 7A BC AF 27 1C }

    condition:
        // Encrypted ZIP entries set the low bit of the general purpose flag.
        ($zip at 0 and uint16(6) == 0x0001) or $rar at 0 or $sevenzip at 0
}

/*
    There is deliberately no PDF rule here.

    A PDF that runs script on open is already reported by the inspector's own
    walk of the format, which separates /OpenAction from /JavaScript from
    /Launch rather than collapsing them into one match. A rule saying the same
    thing produced a second finding for one fact, which is noise in a report and
    a double count in any score built from it. Rules cover what walking the
    container cannot.
*/
