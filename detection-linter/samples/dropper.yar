rule Good_Example_Dropper
{
    meta:
        author = "ctimmons"
        description = "Three distinct markers of a known dropper"
    strings:
        $s1 = "DropperConfigBlock" fullword
        $s2 = "C:\\ProgramData\\svc\\payload.bin" wide
        $s3 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        2 of ($s*)
}
