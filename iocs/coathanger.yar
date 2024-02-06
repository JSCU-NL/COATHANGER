rule COATHANGER_beacon
{
    meta:
        description = "Detects COATHANGER beaconing code (GET / HTTP/2\nHost: www.google.com\n\n)"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
    strings:
        $chunk_1 = {
            48 B8 47 45 54 20 2F 20 48 54
            48 89 45 B0
            48 B8 54 50 2F 32 0A 48 6F 73
            48 89 45 B8
            48 B8 74 3A 20 77 77 77 2E 67
            48 89 45 C0
            48 B8 6F 6F 67 6C 65 2E 63 6F
        }

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        any of them
}


rule COATHANGER_files
{
    meta:
        description = "Detects COATHANGER files by used filenames"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
    strings:
        $1 = "/data2/"
        $2 = "/httpsd"
        $3 = "/preload.so"
        $4 = "/authd"
        $5 = "/tmp/packfile"
        $6 = "/smartctl"
        $7 = "/etc/ld.so.preload"
        $8 = "/newcli"
        $9 = "/bin/busybox"

    condition:
        (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
        and filesize < 5MB and 4 of them
}
