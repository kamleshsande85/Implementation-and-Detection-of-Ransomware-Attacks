rule RansomwareNote
{
    strings:
        $note = "Your files are encrypted! Pay to decrypt." nocase
    condition:
        $note
}
