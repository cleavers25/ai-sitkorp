/*
  Bundled webshell heuristics for AI Infra Assistant (Phase 2).
  Intentionally small and conservative: each rule needs PHP code plus a dangerous construct.
  Findings are reported as SUSPECTED and must be reviewed by a human.
*/

private rule is_php
{
    strings:
        $php = "<?php" nocase
        $short = "<?="
    condition:
        $php at 0 or $short at 0 or $php in (0..1024)
}

rule PHP_Eval_Encoded_Payload
{
    meta:
        description = "eval() of a decoded/decompressed payload"
        severity = "HIGH"
    strings:
        $a = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin)\s*\(/ nocase
    condition:
        is_php and $a
}

rule PHP_Exec_From_Request
{
    meta:
        description = "OS command execution fed directly from request input"
        severity = "CRITICAL"
    strings:
        $a = /(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $b = /(assert|create_function)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $c = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        is_php and any of them
}

rule PHP_Known_Webshell_Marker
{
    meta:
        description = "Strings found in well-known public webshells"
        severity = "CRITICAL"
    strings:
        $s1 = "FilesMan" ascii
        $s2 = "b374k" ascii nocase
        $s3 = "IndoXploit" ascii nocase
        $s4 = "r57shell" ascii nocase
        $s5 = "c99shell" ascii nocase
        $s6 = "WSO " ascii
        $s7 = "AlfaTeam" ascii nocase
        $s8 = "Mini Shell" ascii nocase
        $s9 = "uname -a" ascii
        $s10 = "move_uploaded_file" ascii
    condition:
        is_php and (any of ($s1, $s2, $s3, $s4, $s5, $s7, $s8) or ($s6 and $s9) or ($s9 and $s10))
}

rule PHP_Heavy_Obfuscation
{
    meta:
        description = "Very long encoded blob combined with a decoder"
        severity = "HIGH"
    strings:
        $blob = /['"][A-Za-z0-9+\/=]{2000,}['"]/
        $d1 = "base64_decode" nocase
        $d2 = "gzinflate" nocase
        $d3 = "str_rot13" nocase
    condition:
        is_php and $blob and any of ($d*)
}
