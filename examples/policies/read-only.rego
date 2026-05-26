# Allow GET / HEAD only. Useful for read-only mirroring of an upstream.
package proxy.authz

default allow := false

allowed_methods := {"GET", "HEAD"}

allow if {
    allowed_methods[input.request.method]
}
