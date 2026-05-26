# Allow only POSTs to /v1/chat/completions on OpenAI.
# Blocks embeddings, files, assistants, fine-tuning, everything else.
package proxy.authz

default allow := false

allow if {
    input.request.method == "POST"
    input.request.path == "/v1/chat/completions"
}
