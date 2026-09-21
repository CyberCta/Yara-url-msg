rule MSG_HTTP_URLs
{
    meta:
        description = "Extract HTTP(S) URLs from ASCII or UTF-8 text, preserving query strings"
    strings:
        $url = /https?:\/\/[^\x00-\x20\x7f"'<>\\]+/ ascii nocase
    condition:
        $url
}
