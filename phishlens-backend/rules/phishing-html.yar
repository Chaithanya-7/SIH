/*
    HTML and SVG attachments.

    An HTML attachment is a whole web page delivered past the web. It does not
    need a link to a phishing site because it *is* the phishing site, running
    from a local file with no domain for anybody to inspect and no reputation
    for anybody to check. The same is true of SVG, which most people read as an
    image and which browsers will happily execute script inside.

    Every rule here describes structure. None of them look for persuasive
    wording: an attacker writing copy with a language model changes the words
    and cannot change the fact that a credential form has to post somewhere.
*/

rule HTML_Smuggling_Blob_Download
{
    meta:
        description = "An HTML attachment that assembles a file in the browser and saves it"
        rationale = "The payload never crosses the network as a file, so nothing between the sender and the person can scan it. It is built from text inside the page after it opens."
        severity = "HIGH"
        decisive = true
        technique = "T1027.006"

    strings:
        $blob = "new Blob(" nocase
        $url = "createObjectURL" nocase
        $anchor = "document.createElement('a')" nocase
        $anchor2 = "document.createElement(\"a\")" nocase
        $download = ".download" nocase
        $click = ".click()" nocase
        $b64 = "atob(" nocase

    condition:
        filesize < 5MB
        and $blob and $url
        and any of ($anchor, $anchor2)
        and $download and $click and $b64
}

rule HTML_Credential_Form_Posting_Offsite
{
    meta:
        description = "A local HTML file containing a password field that submits to a remote address"
        rationale = "A sign-in page that arrives as an attachment has no reason to exist. The form action is where the typed password is sent."
        severity = "HIGH"
        decisive = true

    strings:
        $password = /<input[^>]{0,200}type\s*=\s*["']?password/ nocase
        $action = /<form[^>]{0,200}action\s*=\s*["']https?:\/\// nocase
        $html = "<html" nocase

    condition:
        filesize < 3MB and $html and $password and $action
}

rule SVG_With_Embedded_Script
{
    meta:
        description = "An SVG image carrying script or a foreign object"
        rationale = "SVG is treated as a picture by the person receiving it and as a document by the browser. Script inside one runs when it is opened."
        severity = "HIGH"

    strings:
        $svg = "<svg" nocase
        $script = "<script" nocase
        $foreign = "<foreignObject" nocase
        $handler = /on(load|click|error|mouseover)\s*=/ nocase
        $b64 = "base64," nocase

    condition:
        filesize < 3MB and $svg and (
            $script or $foreign or ($handler and $b64)
        )
}

rule HTML_Meta_Refresh_To_Encoded_Page
{
    meta:
        description = "A page that immediately redirects itself into an encoded document"
        rationale = "The address bar never shows a destination worth reading, and the destination is carried in the page rather than fetched, so there is nothing to look up."
        severity = "HIGH"
        decisive = true

    strings:
        $refresh = /<meta[^>]{0,120}http-equiv\s*=\s*["']?refresh/ nocase
        $data = "url=data:text/html" nocase
        $b64 = ";base64," nocase

    condition:
        filesize < 2MB and $refresh and $data and $b64
}

rule HTML_Clipboard_Paste_To_Run
{
    meta:
        description = "A page that copies a command and instructs the reader to run it"
        rationale = "The page performs no exploit at all: it writes a command to the clipboard and asks the person to paste it into the Run dialog or a terminal, so the person becomes the delivery mechanism."
        severity = "HIGH"
        decisive = true
        technique = "T1204.004"

    strings:
        $clip1 = "navigator.clipboard.writeText" nocase
        $clip2 = "execCommand('copy')" nocase
        $clip3 = "execCommand(\"copy\")" nocase
        $run1 = "Windows + R" nocase
        $run2 = "Win+R" nocase
        $run3 = "Windows Key + R" nocase
        $run4 = "press CTRL + V" nocase
        $shell1 = "powershell" nocase
        $shell2 = "mshta" nocase
        $shell3 = "cmd.exe" nocase

    condition:
        filesize < 3MB
        and any of ($clip*)
        and any of ($run*)
        and any of ($shell*)
}

rule HTML_Obfuscated_Body_Only
{
    meta:
        description = "An HTML file whose entire content is assembled from encoded text at runtime"
        rationale = "A page written this way cannot be read before it runs, which is the purpose. Ordinary mail-generated HTML does not need to hide itself."
        severity = "MEDIUM"

    strings:
        $write = "document.write(" nocase
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $atob = "atob(" nocase
        $fromchar = "String.fromCharCode(" nocase
        $html = "<html" nocase

    condition:
        filesize < 3MB and $html
        and (($write or $eval) and ($unescape or $atob or $fromchar))
}
