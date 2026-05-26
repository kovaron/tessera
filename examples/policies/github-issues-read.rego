# Allow read-only access to the GitHub issues API for one repo only.
# Adjust the path prefix for your repo.
package proxy.authz

default allow := false

allow if {
    input.request.method == "GET"
    startswith(input.request.path, "/repos/acme/widgets/issues")
}
