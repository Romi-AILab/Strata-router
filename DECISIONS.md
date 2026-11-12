# Decision records

A closed question, written so it stays closed: the verdict, the evidence
that settled it, and the one thing that could reopen it. Re-researching an
entry from scratch is waste; new primary evidence that contradicts a numbered
point below is what justifies a re-run.

## 2026-11 -- Hosted web search: no "recovery" inside this router, ever

**Reported symptom.** A client behind a converting shim (a `cc-switch`-style
model switcher) calls its built-in web search and gets nothing back. The
proposed fix was to have this router implement search "recovery".

**Verdict: rejected -- and not as backlog that lost a vote. A middle relay
cannot execute these tools in the first place, on any chain this router is
built for.**

1. **Who runs the search.** Anthropic's Messages API docs say it verbatim
   about these tool kinds: "Server tools run on Anthropic's infrastructure,
   with no handler code in your application" and "Claude runs the search on
   Anthropic's infrastructure and returns the cited results in the same
   response." The tool definition in a request is a delegation slip: the
   searcher is the Anthropic-family endpoint that received the request, not
   any hop in front of it.

2. **What executing one would actually cost.** The documented contract --
   pause-turn continuation, encrypted content blocks required or the API
   rejects the resume, citation obligations, per-search billing -- makes
   whoever executes a server tool a stateful protocol party holding a third
   party's search account. Rule 1 is this design's perimeter: a relay that
   opens, interprets and completes server-tool turns is no longer this
   router.

3. **The category is anchored, not a list.** The Messages API tool reference
   marks each tool's `Execution` side. The server-executed family spans at
   least six kinds (search, fetch, code execution, advisor, tool-search,
   MCP toolset) and grows, while lookalikes (memory, bash, text editor,
   computer, browser) are client-executed -- and availability is
   per-platform asymmetric (one host runs the tool-search tools but is not
   listed for web search). Anything in this repo that ENUMERATES the kinds
   rots; the *Limits* bullet therefore anchors on the `Execution` column
   instead of a closed list.

4. **The drop is upstream of here, and upstream chose honesty.** The public
   tracker of the cc-switch shim says it plainly: an open PR titled "fail
   closed on Anthropic hosted tools for chat-completions upstreams" (#6410,
   unmerged), plus open issues documenting local routing dropping
   `web_search` (#5233) and mis-converting it into a plain function that
   then answers "Did 0 searches" (#9059). A converting shim drops or
   rewrites these definitions before they reach any router -- so any
   router-side counter or hook would read zero on such chains, forever.

5. **The categorical statement.** On a chain with no Anthropic-family
   endpoint, hosted search has nowhere to execute. No middle hop can
   restore what only the far end can run -- and even the shim's own
   maintainers chose honest failure over emulation.

**What shipped instead (v1.2.18 doc batch).** A *Limits* bullet in
`router/README.md` states the mechanism and where the capability actually
lives: a client-executed search tool (e.g. a local web-search MCP server),
or disabling the built-in search for that provider so the model stops
calling a tool nobody runs.

**Would reopen it.** Anthropic documenting a client-executable form of these
tools (the `Execution` column defines the category), or a verified
non-converting provider path that makes a relay-side visibility counter
non-zero by construction -- that counter is parked, not rejected, under
exactly those preconditions.

*Process note: this entry closes a four-round, eight-reviewer L2 research
program with blind convergence (80-row primary-source claim ledger, zero
phantom citations). The verdict and the numbered evidence above are what
this repo needs; the review program's files live outside it.*
