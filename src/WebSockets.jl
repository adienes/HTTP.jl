module WebSockets

using Base64, UUIDs, Sockets, Random
using Random: Xoshiro
using MbedTLS: digest, MD_SHA1, SSLContext
using ..IOExtras, ..Streams, ..Connections, ..Messages, ..Conditions, ..Servers
import ..PerMessageDeflate as PMD
using ..Exceptions: current_exceptions_to_string
import ..open
import ..HTTP # for doc references

export WebSocket, send, send_batch, receive, ping, pong, stats

# 1st 2 bytes of a frame
primitive type FrameFlags 16 end
uint16(x::FrameFlags) = Base.bitcast(UInt16, x)
FrameFlags(x::UInt16) = Base.bitcast(FrameFlags, x)

const WS_FINAL =  0b1000000000000000
const WS_RSV1 =   0b0100000000000000
const WS_RSV2 =   0b0010000000000000
const WS_RSV3 =   0b0001000000000000
const WS_OPCODE = 0b0000111100000000
const WS_MASK =   0b0000000010000000
const WS_LEN =    0b0000000001111111

@enum OpCode::UInt8 CONTINUATION=0x00 TEXT=0x01 BINARY=0x02 CLOSE=0x08 PING=0x09 PONG=0x0A

iscontrol(opcode::OpCode) = opcode > BINARY

Base.propertynames(x::FrameFlags) = (:final, :rsv1, :rsv2, :rsv3, :opcode, :mask, :len)
function Base.getproperty(x::FrameFlags, nm::Symbol)
    ux = uint16(x)
    if nm == :final
        return ux & WS_FINAL > 0
    elseif nm == :rsv1
        return ux & WS_RSV1 > 0
    elseif nm == :rsv2
        return ux & WS_RSV2 > 0
    elseif nm == :rsv3
        return ux & WS_RSV3 > 0
    elseif nm == :opcode
        return OpCode(((ux & WS_OPCODE) >> 8) % UInt8)
    elseif nm == :masked
        return ux & WS_MASK > 0
    elseif nm == :len
        return ux & WS_LEN
    end
end

FrameFlags(final::Bool, opcode::OpCode, masked::Bool, len::Integer; rsv1::Bool=false, rsv2::Bool=false, rsv3::Bool=false) =
    FrameFlags(
        (final ? WS_FINAL : UInt16(0)) |
        (rsv1 ? WS_RSV1 : UInt16(0)) | (rsv2 ? WS_RSV2 : UInt16(0)) | (rsv3 ? WS_RSV3 : UInt16(0)) |
        (UInt16(opcode) << 8) |
        (masked ? WS_MASK : UInt16(0)) |
        (len % UInt16)
    )

Base.show(io::IO, x::FrameFlags) =
    print(io, "FrameFlags(", "final=", x.final, ", ", "opcode=", x.opcode, ", ", "masked=", x.masked, ", ", "len=", x.len, ")")

# Chunked XOR-mask: process 8 bytes at a time using a 64-bit broadcast of the
# 32-bit masking key, scalar tail for the last <8 bytes. ~8-11x faster than
# a byte-by-byte loop on payloads >256 bytes and stays cache-bandwidth
# limited beyond that. Matches RFC 6455 §5.3 mask semantics:
#   result[i] = data[i] XOR key[i mod 4]
# where key byte 0 is the low byte of `mask_u32` in host order.
#
# `range_start` and `range_len` are 1-indexed; the unmask covers
# `bytes[range_start : range_start + range_len - 1]`.
function mask!(bytes::AbstractVector{UInt8}, mask_u32::UInt32, range_start::Int=1, range_len::Integer=length(bytes))
    range_len <= 0 && return
    @boundscheck (range_start >= 1 && range_start + range_len - 1 <= length(bytes)) ||
        throw(BoundsError(bytes, range_start:range_start+range_len-1))
    m64 = (UInt64(mask_u32) << 32) | UInt64(mask_u32)
    nchunks = range_len >> 3
    GC.@preserve bytes begin
        p = pointer(bytes, range_start)
        @inbounds for i in 0:(nchunks - 1)
            q = p + (i << 3)
            unsafe_store!(Ptr{UInt64}(q), unsafe_load(Ptr{UInt64}(q)) ⊻ m64)
        end
        tail_off = nchunks << 3
        tail_n = range_len & 7
        @inbounds for i in 0:(tail_n - 1)
            q = p + tail_off + i
            k = (mask_u32 >> (8 * (i & 3))) % UInt8
            unsafe_store!(q, unsafe_load(q) ⊻ k)
        end
    end
    return
end

# If _The WebSocket Connection is Closed_ and no Close control frame was received by the
# endpoint (such as could occur if the underlying transport connection
# is lost), _The WebSocket Connection Close Code_ is considered to be 1006.
@noinline iocheck(io) = isopen(io) || throw(WebSocketError(CloseFrameBody(1006, "WebSocket connection is closed")))

# Maximum websocket header length: 2 flags + 8 ext-len + 4 mask = 14 bytes.
const WS_MAX_HEADER = 14

# Header length for a frame with `payloadlen` bytes and `masked`.
@inline function header_len_for(payloadlen::Integer, masked::Bool)
    base = payloadlen < 0x7E ? 2 :
           payloadlen <= 0xFFFF ? 4 : 10
    return base + (masked ? 4 : 0)
end

# Build the websocket frame header into `buf[at+1 : at+header_len_for(...)]`.
# Caller guarantees the buffer is large enough. Layout follows RFC 6455 §5.2.
# `at=0` (default) writes at the start of the buffer; non-zero `at` lets
# `send_batch` write multiple frames back-to-back into a single buffer.
@inline function write_header!(buf::Vector{UInt8}, final::Bool, opcode::OpCode,
                               masked::Bool, payloadlen::Integer, mask_u32::UInt32;
                               at::Int=0,
                               rsv1::Bool=false, rsv2::Bool=false, rsv3::Bool=false)
    b1 = (final ? 0x80 : 0x00) |
         (rsv1 ? 0x40 : 0x00) | (rsv2 ? 0x20 : 0x00) | (rsv3 ? 0x10 : 0x00) |
         (UInt8(opcode) & 0x0F)
    if payloadlen < 126
        len7 = UInt8(payloadlen); extb = 0
    elseif payloadlen <= 0xFFFF
        len7 = 0x7E; extb = 2
    else
        len7 = 0x7F; extb = 8
    end
    b2 = (masked ? 0x80 : 0x00) | len7
    @inbounds buf[at + 1] = b1
    @inbounds buf[at + 2] = b2
    pos = at + 3
    GC.@preserve buf begin
        if extb == 2
            unsafe_store!(Ptr{UInt16}(pointer(buf, pos)), hton(UInt16(payloadlen)))
            pos += 2
        elseif extb == 8
            unsafe_store!(Ptr{UInt64}(pointer(buf, pos)), hton(UInt64(payloadlen)))
            pos += 8
        end
        if masked
            # Stored in host byte order to match wire convention on little-endian:
            # the low byte of `mask_u32` ends up first on the wire, matching
            # mask!'s key[i] = (mask_u32 >> 8*(i mod 4)) & 0xFF.
            unsafe_store!(Ptr{UInt32}(pointer(buf, pos)), mask_u32)
            pos += 4
        end
    end
    return pos - 1 - at
end

# Encode one frame into `buf[offset+1 : new_offset]` and return `new_offset`.
# Does NOT touch the socket. Shared by `write_frame!` (single frame),
# `send_batch` (N frames coalesced), and the permessage-deflate send path
# (which sets `rsv1=true` to signal compression).
@inline function _encode_frame!(ws, buf::Vector{UInt8}, offset::Int, final::Bool,
                                opcode::OpCode, payload_data::AbstractVector{UInt8};
                                rsv1::Bool=false)
    payloadlen = length(payload_data)
    masked = ws.client
    hlen = header_len_for(payloadlen, masked)
    mask_u32 = masked ? ws_mask(ws) : UInt32(0)
    write_header!(buf, final, opcode, masked, payloadlen, mask_u32; at=offset, rsv1=rsv1)
    if payloadlen > 0
        copyto!(buf, offset + hlen + 1, payload_data, firstindex(payload_data), payloadlen)
        if masked
            mask!(buf, mask_u32, offset + hlen + 1, payloadlen)
        end
    end
    return offset + hlen + payloadlen
end

# Generate a 32-bit masking key from the WebSocket's per-connection RNG.
# RFC 6455 §5.3 only requires the key to be unpredictable per frame; we do
# not need crypto-grade randomness, and over TLS the mask is cosmetic.
# Type annotation deferred to call site so this can be defined before
# the WebSocket struct without forward-declaration gymnastics.
@inline ws_mask(ws) = rand(ws.rng, UInt32)

# Low-level: emit one fully-prepared frame from `ws.writebuffer[1:total_len]`
# in a single `unsafe_write`. Caller must hold `ws.writelock`.
@inline function emit_frame!(ws, total_len::Int)
    buf = ws.writebuffer
    n = GC.@preserve buf unsafe_write(ws.io, pointer(buf), UInt(total_len))
    return Int(n)
end

# Encode one frame and write it out via the WebSocket's preallocated buffer.
# Replaces the per-frame `IOBuffer + take!` pattern in `writeframe`: builds
# the header in place, copies/masks the payload after it, emits a single
# `unsafe_write`. The buffer grows monotonically to its high-water mark, so
# steady-state HFT use is alloc-free.
function write_frame!(ws, final::Bool, opcode::OpCode, payload_data::AbstractVector{UInt8})
    payloadlen = length(payload_data)
    masked = ws.client
    total = header_len_for(payloadlen, masked) + payloadlen
    if length(ws.writebuffer) < total
        resize!(ws.writebuffer, total)
    end
    _encode_frame!(ws, ws.writebuffer, 0, final, opcode, payload_data)
    n = emit_frame!(ws, total)
    # Frame-level metrics (includes control frames). `bytes_sent` counts only
    # data frame payload bytes — that's what HFT operators usually want to
    # graph; control frame chatter is tracked via ping_count separately.
    s = ws.stats
    s.frames_sent += 1
    if opcode == TEXT || opcode == BINARY || opcode == CONTINUATION
        s.bytes_sent += payloadlen
        s.compressed_bytes_sent += payloadlen  # no compression in this path
    end
    return n
end

# Empty-payload convenience used by control frames.
write_frame!(ws, final::Bool, opcode::OpCode, ::Nothing) =
    write_frame!(ws, final, opcode, UInt8[])

"Status codes according to RFC 6455 7.4.1"
const STATUS_CODE_DESCRIPTION = Dict{Int, String}(
    1000=>"Normal",                     1001=>"Going Away",
    1002=>"Protocol Error",             1003=>"Unsupported Data",
    1004=>"Reserved",                   1005=>"No Status Recvd- reserved",
    1006=>"Abnormal Closure- reserved", 1007=>"Invalid frame payload data",
    1008=>"Policy Violation",           1009=>"Message too big",
    1010=>"Missing Extension",          1011=>"Internal Error",
    1012=>"Service Restart",            1013=>"Try Again Later",
    1014=>"Bad Gateway",                1015=>"TLS Handshake")

@noinline validclosecheck(x) = (1000 <= x < 5000 && !(x in (1004, 1005, 1006, 1016, 1100, 2000, 2999))) || throw(WebSocketError(CloseFrameBody(1002, "Invalid close status code")))

"""
    WebSockets.CloseFrameBody(status, message)

Represents the payload of a CLOSE control websocket frame.
For error close `status`, it can be wrapped in a `WebSocketError`
and thrown.
"""
struct CloseFrameBody
    status::Int
    message::String
end

struct WebSocketError <: Exception
    message::Union{String, CloseFrameBody}
end

"""
    WebSockets.isok(x::WebSocketError) -> Bool

Returns true if the `WebSocketError` has a non-error status code.
When calling `receive(websocket)`, if a CLOSE frame is received,
the CLOSE frame body is parsed and thrown inside the `WebSocketError`,
but if the CLOSE frame has a non-error status code, it's safe to
ignore the error and return from the `WebSockets.open` or `WebSockets.listen`
calls without throwing.
"""
isok(x) = x isa WebSocketError && x.message isa CloseFrameBody && (x.message.status == 1000 || x.message.status == 1001 || x.message.status == 1005)

"""
    WebSocketStats

Per-connection counters useful for observability and the heartbeat
mechanism. Fields are mutated from the send / receive / heartbeat paths
of a single WebSocket and read via [`stats`](@ref). All counters use
`Int` (process word) and increments are not synchronized — they're
intended for monitoring, not transactional reads.

Fields:

- `messages_sent::Int`, `messages_received::Int` — fully-assembled
  application messages (control frames not counted).
- `frames_sent::Int`, `frames_received::Int` — includes data fragments
  but excludes control frames.
- `bytes_sent::Int`, `bytes_received::Int` — payload bytes only
  (header / mask bytes excluded).
- `ping_count::Int`, `pong_count::Int` — PINGs we sent / PONGs we
  observed in the receive path.
- `last_pong::Float64` — wall-clock time (seconds since epoch) of the
  most recent PONG; `0.0` if none yet.
- `last_recv_time::Float64` — wall-clock time of the last *data*
  message; `0.0` if none yet.
- `recv_size_buckets::NTuple{6,Int}` — message-size histogram:
  `(<64, 64–255, 256–1023, 1024–4095, 4096–16383, >=16384)` bytes.
"""
mutable struct WebSocketStats
    messages_sent::Int
    messages_received::Int
    frames_sent::Int
    frames_received::Int
    bytes_sent::Int
    bytes_received::Int
    # On a permessage-deflate connection these track the wire-bytes (post-
    # compress on send, pre-decompress on recv) so operators can compute the
    # compression ratio as `compressed_bytes_sent / bytes_sent`. Equal to
    # bytes_sent / bytes_received when the extension is not negotiated.
    compressed_bytes_sent::Int
    compressed_bytes_received::Int
    ping_count::Int
    pong_count::Int
    last_pong::Float64
    last_recv_time::Float64
    recv_size_buckets::NTuple{6,Int}
end
WebSocketStats() = WebSocketStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, (0,0,0,0,0,0))

"""
    PMDContext

Per-WebSocket permessage-deflate state. Holds the deflate / inflate
contexts and reusable scratch buffers for compressed payloads. Created
on handshake when `permessage_deflate=true` is negotiated, finalised
in `close(ws)`.
"""
mutable struct PMDContext
    deflate::PMD.ZStream
    inflate::PMD.ZStream
    # Output buffer for compressed payload (send path). Grown to high-water mark.
    deflate_out::Vector{UInt8}
    # Output buffer for decompressed payload (receive path).
    inflate_out::Vector{UInt8}
    # finalize() must be called exactly once.
    closed::Bool
end
function PMDContext()
    d = PMD.ZStream(); PMD.deflate_init!(d)
    i = PMD.ZStream(); PMD.inflate_init!(i)
    ctx = PMDContext(d, i, UInt8[], UInt8[], false)
    finalizer(_pmd_close!, ctx)
    return ctx
end
function _pmd_close!(ctx::PMDContext)
    ctx.closed && return
    ctx.closed = true
    try; PMD.deflate_end!(ctx.deflate); catch; end
    try; PMD.inflate_end!(ctx.inflate); catch; end
    return
end

@inline function _bump_recv_size!(s::WebSocketStats, n::Int)
    b = s.recv_size_buckets
    i = n < 64       ? 1 :
        n < 256      ? 2 :
        n < 1024     ? 3 :
        n < 4096     ? 4 :
        n < 16384    ? 5 :
                       6
    s.recv_size_buckets = ntuple(j -> j == i ? b[j] + 1 : b[j], 6)
    return
end

"""
    WebSocket(io::HTTP.Connection, req, resp; client=true)

Representation of a websocket connection.
Use `WebSockets.open` to open a websocket connection, passing a
handler function `f(ws)` to send and receive messages.
Use `WebSockets.listen` to listen for incoming websocket connections,
passing a handler function `f(ws)` to send and receive messages.

Call `send(ws, msg)` to send a message; if `msg` is an `AbstractString`,
a TEXT websocket message will be sent; if `msg` is an `AbstractVector{UInt8}`,
a BINARY websocket message will be sent. Otherwise, `msg` should be an iterable
of either `AbstractString` or `AbstractVector{UInt8}`, and a fragmented message
will be sent, one frame for each iterated element.

Control frames can be sent by calling `ping(ws[, data])`, `pong(ws[, data])`,
or `close(ws[, body::WebSockets.CloseFrameBody])`. Calling `close` will initiate
the close sequence and close the underlying connection.

To receive messages, call `receive(ws)`, which will block until a non-control,
full message is received. PING messages will automatically be responded to when
received. CLOSE messages will also be acknowledged and then a `WebSocketError`
will be thrown with the `WebSockets.CloseFrameBody` payload, which may include
a non-error CLOSE frame status code. `WebSockets.isok(err)` can be called to
check if the CLOSE was normal or unexpected. Fragmented messages will be
received until the final frame is received and the full concatenated payload
can be returned. `receive(ws)` returns a `Vector{UInt8}` for BINARY messages,
and a `String` for TEXT messages.

For convenience, `WebSocket`s support the iteration protocol, where each iteration
will `receive` a non-control message, with iteration terminating when the connection
is closed. E.g.:
```julia
WebSockets.open(url) do ws
    for msg in ws
        # do cool stuff with msg
    end
end
```
"""
mutable struct WebSocket
    id::UUID
    io::Connection
    request::Request
    response::Response
    maxframesize::Int
    maxfragmentation::Int
    client::Bool
    readbuffer::Vector{UInt8}
    writebuffer::Vector{UInt8}
    # Pre-sized scratch for inline control frame payloads (PING/PONG/CLOSE).
    # RFC 6455 caps control payloads at 125 bytes; we keep this buffer at its
    # max size permanently so ping-heavy feeds never allocate on receive.
    ctlbuffer::Vector{UInt8}
    # Pre-sized scratch for the variable-length frame header. Largest header
    # is 14 bytes (2 flags + 8 ext-len + 4 mask). Used by the receive fast
    # path so we don't allocate a `Ref{T}` per call to read(io, T).
    headerbuf::Vector{UInt8}
    # message_len tracks the assembled payload length in readbuffer for the
    # receive paths (frame data is accumulated in readbuffer and message_len
    # marks the valid prefix).
    message_len::Int
    readclosed::Bool
    writeclosed::Bool
    # Per-WS PRNG for masking-key generation. Seeded once from RandomDevice
    # to avoid a /dev/urandom syscall per outgoing client frame.
    rng::Xoshiro
    # Serializes the write path so multiple producer tasks sharing a
    # WebSocket can call send/ping/pong concurrently without corrupting
    # `writebuffer`. Cheap (uncontended) in the single-writer case.
    writelock::ReentrantLock
    # Background Timer that pings at `ping_interval` and closes the socket
    # if no PONG has arrived within `pong_timeout`. `nothing` when heartbeat
    # is disabled. `close` cancels it.
    heartbeat::Union{Timer,Nothing}
    # Operational metrics. See [`WebSocketStats`](@ref) / [`stats`](@ref).
    stats::WebSocketStats
    # RFC 7692 permessage-deflate context; `nothing` when the extension was
    # not negotiated. Created during handshake by `open` / `upgrade`.
    pmd::Union{PMDContext,Nothing}
    # Auxiliary buffer used by the receive path when a compressed message is
    # spread across multiple frames. Compressed bytes accumulate here; once
    # the FIN frame arrives we inflate into `pmd.inflate_out` and copy back
    # into `readbuffer` so receive() sees a uniform layout.
    compressed_buffer::Vector{UInt8}
end

const DEFAULT_MAX_FRAG = 1024

IOExtras.tcpsocket(ws::WebSocket) = tcpsocket(ws.io)

function WebSocket(io::Connection, req=Request(), resp=Response();
                   client::Bool=true,
                   maxframesize::Integer=typemax(Int),
                   maxfragmentation::Integer=DEFAULT_MAX_FRAG)
    rng = Xoshiro(rand(Random.RandomDevice(), UInt64),
                  rand(Random.RandomDevice(), UInt64),
                  rand(Random.RandomDevice(), UInt64),
                  rand(Random.RandomDevice(), UInt64))
    return WebSocket(uuid4(), io, req, resp, maxframesize, maxfragmentation, client,
                     UInt8[], UInt8[],
                     Vector{UInt8}(undef, 125),           # ctlbuffer
                     Vector{UInt8}(undef, WS_MAX_HEADER), # headerbuf
                     0, false, false, rng, ReentrantLock(),
                     nothing,                             # heartbeat timer
                     WebSocketStats(),                    # stats
                     nothing,                             # pmd (set by handshake)
                     UInt8[])                             # compressed_buffer
end

"""
    stats(ws::WebSocket) -> WebSocketStats

Return the live `WebSocketStats` object for `ws`. The fields are
updated in place on every send and receive; this returns the struct
itself (no copy), so the caller can sample it as the connection runs.
See `WebSocketStats` for the field reference.

```julia
WebSockets.open(url) do ws
    @async for _ in ws; end
    while !WebSockets.isclosed(ws)
        s = WebSockets.stats(ws)
        @info "recv" msgs=s.messages_received bytes=s.bytes_received
        sleep(1)
    end
end
```
"""
stats(ws::WebSocket) = ws.stats

"""
    WebSockets.isclosed(ws) -> Bool

Check whether a `WebSocket` has sent and received CLOSE frames.
"""
isclosed(ws::WebSocket) = ws.readclosed && ws.writeclosed

# Handshake
"Check whether a HTTP.Request or HTTP.Response is a websocket upgrade request/response"
function isupgrade(r::Message)
    ((r isa Request && r.method == "GET") ||
     (r isa Response && r.status == 101)) &&
    (hasheader(r, "Connection", "upgrade") ||
     hasheader(r, "Connection", "keep-alive, upgrade")) &&
    hasheader(r, "Upgrade", "websocket")
end

# Renamed in HTTP@1
@deprecate is_upgrade isupgrade

@noinline handshakeerror() = throw(WebSocketError(CloseFrameBody(1002, "Websocket handshake failed")))

function hashedkey(key)
    hashkey = "$(strip(key))258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64encode(digest(MD_SHA1, hashkey))
end

# Returns true if `msg`'s Sec-WebSocket-Extensions header indicates the
# server accepted permessage-deflate (with any parameters). We don't
# validate the specific parameters since we implement no_context_takeover
# for both directions regardless of negotiation outcome — sub-optimal but
# always wire-compatible.
function _server_accepted_pmd(msg)
    h = header(msg, "Sec-WebSocket-Extensions", "")
    return occursin("permessage-deflate", lowercase(h))
end

# Returns true if the client offered permessage-deflate.
_client_offers_pmd(http) = _server_accepted_pmd(http.message)

"""
    WebSockets.open(handler, url; verbose=false, kw...)

Initiate a websocket connection to `url` (which should have schema like `ws://` or `wss://`),
and call `handler(ws)` with the websocket connection. Passing `verbose=true` or `verbose=2`
will enable debug logging for the life of the websocket connection.
`handler` should be a function of the form `f(ws) -> nothing`, where `ws` is a [`WebSocket`](@ref).
Supported keyword arguments are the same as supported by [`HTTP.request`](@ref).
Typical websocket usage is:
```julia
WebSockets.open(url) do ws
    # iterate incoming websocket messages
    for msg in ws
        # send message back to server or do other logic here
        send(ws, msg)
    end
    # iteration ends when the websocket connection is closed by server or error
end
```
"""

# Start a heartbeat Timer that sends a PING every `interval` seconds and
# closes the underlying socket if no PONG has arrived within `timeout`.
# Returns the Timer (so callers can stash it on `ws.heartbeat` and the
# socket-close path can stop it). `interval === nothing` means no heartbeat.
function _start_heartbeat!(ws::WebSocket, interval::Union{Nothing,Real}, timeout::Real)
    interval === nothing && return nothing
    # Prime last_pong so the first interval doesn't immediately fire as stale.
    ws.stats.last_pong = time()
    iv = Float64(interval)
    to = Float64(timeout)
    t = Timer(iv; interval=iv) do _
        # Drop out if the socket is already gone — the timer will be
        # closed shortly via the close() path or via finalization.
        try
            (ws.writeclosed || ws.readclosed || !isopen(ws.io)) && return
        catch
            return
        end
        if time() - ws.stats.last_pong > to
            try
                isopen(ws.io) && close(ws.io)
            catch
            end
            return
        end
        try
            ping(ws)
        catch
            # writeclosed mid-flight, broken pipe, etc. — let the receive
            # loop see the failure on its next read.
        end
    end
    ws.heartbeat = t
    return t
end

function open(f::Function, url; suppress_close_error::Bool=false, verbose=false, headers=[], maxframesize::Integer=typemax(Int), maxfragmentation::Integer=DEFAULT_MAX_FRAG, nagle::Bool=false, quickack::Bool=true, ping_interval::Union{Nothing,Real}=nothing, pong_timeout::Union{Nothing,Real}=nothing, permessage_deflate::Bool=false, kw...)
    key = base64encode(rand(Random.RandomDevice(), UInt8, 16))
    headers = [
        "Upgrade" => "websocket",
        "Connection" => "Upgrade",
        "Sec-WebSocket-Key" => key,
        "Sec-WebSocket-Version" => "13",
        headers...
    ]
    if permessage_deflate
        # Offer the simplest interoperable form: bare permessage-deflate
        # plus no_context_takeover on both sides. RFC 7692 servers are
        # required to honor or refuse; if refused, we run uncompressed.
        push!(headers, "Sec-WebSocket-Extensions" =>
              "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
    end
    # HTTP.open
    open("GET", url, headers; verbose=verbose, kw...) do http
        startread(http)
        isupgrade(http.message) || handshakeerror()
        if header(http, "Sec-WebSocket-Accept") != hashedkey(key)
            throw(WebSocketError("Invalid Sec-WebSocket-Accept\n" * "$(http.message)"))
        end
        # later stream logic checks to see if the HTTP message is "complete"
        # by seeing if ntoread is 0, which is typemax(Int) for websockets by default
        # so set it to 0 so it's correctly viewed as "complete" once we're done
        # doing websocket things
        http.ntoread = 0
        io = http.stream
        # Match server-side WebSockets.upgrade: disable Nagle and request
        # immediate ACKs, since websocket framing is application-level and
        # waiting up to 40 ms for TCP coalescing crushes interactive
        # round-trip latency. Latency-sensitive clients (HFT) lived with
        # this on the server but not on the client until now.
        # See https://github.com/JuliaWeb/HTTP.jl/issues/1140.
        let sock = tcpsocket(io)
            if sock.status ∉ (Base.StatusInit, Base.StatusUninit) && isopen(sock)
                try Sockets.nagle(sock, nagle) catch end
                try Sockets.quickack(sock, quickack) catch end
            end
        end
        ws = WebSocket(io, http.message.request, http.message; maxframesize, maxfragmentation)
        # If the server accepted permessage-deflate, attach the compression
        # context. Otherwise leave `pmd === nothing` (no compression).
        if permessage_deflate && _server_accepted_pmd(http.message)
            ws.pmd = PMDContext()
        end
        @debug "$(ws.id): WebSocket opened (pmd=$(ws.pmd !== nothing))"
        # Default pong_timeout to 2x the ping interval, the common heuristic
        # for "the feed is dead" when one side stops responding.
        _pt = pong_timeout === nothing && ping_interval !== nothing ? 2 * Float64(ping_interval) : pong_timeout
        _start_heartbeat!(ws, ping_interval, _pt === nothing ? 0.0 : Float64(_pt))
        try
            f(ws)
        catch e
            if !isok(e)
                suppress_close_error || @error "$(ws.id): error" (e, catch_backtrace())
            end
            if !isclosed(ws)
                if e isa WebSocketError && e.message isa CloseFrameBody
                    close(ws, e.message)
                else
                    close(ws, CloseFrameBody(1008, "Unexpected client websocket error"))
                end
            end
            if !isok(e)
                rethrow()
            end
        finally
            if !isclosed(ws)
                close(ws, CloseFrameBody(1000, ""))
            end
        end
    end
end

"""
    WebSockets.listen(handler, host, port; verbose=false, kw...)
    WebSockets.listen!(handler, host, port; verbose=false, kw...) -> HTTP.Server

Listen for websocket connections on `host` and `port`, and call `handler(ws)`,
which should be a function taking a single `WebSocket` argument.
Keyword arguments `kw...` are the same as supported by [`HTTP.listen`](@ref).
Typical usage is like:
```julia
WebSockets.listen(host, port) do ws
    # iterate incoming websocket messages
    for msg in ws
        # send message back to client or do other logic here
        send(ws, msg)
    end
    # iteration ends when the websocket connection is closed by client or error
end
```
"""
function listen end

listen(f, args...; kw...) = Servers.listen(http -> upgrade(f, http; kw...), args...; kw...)
listen!(f, args...; kw...) = Servers.listen!(http -> upgrade(f, http; kw...), args...; kw...)

function upgrade(f::Function, http::Streams.Stream; suppress_close_error::Bool=false, maxframesize::Integer=typemax(Int), maxfragmentation::Integer=DEFAULT_MAX_FRAG, nagle=false, quickack=true, ping_interval::Union{Nothing,Real}=nothing, pong_timeout::Union{Nothing,Real}=nothing, permessage_deflate::Bool=true, kw...)
    @debug "Server websocket upgrade requested"
    isupgrade(http.message) || handshakeerror()
    if !hasheader(http, "Sec-WebSocket-Version", "13")
        throw(WebSocketError("Expected \"Sec-WebSocket-Version: 13\"!\n" * "$(http.message)"))
    end
    if !hasheader(http, "Sec-WebSocket-Key")
        throw(WebSocketError("Expected \"Sec-WebSocket-Key header\"!\n" * "$(http.message)"))
    end
    setstatus(http, 101)
    setheader(http, "Upgrade" => "websocket")
    setheader(http, "Connection" => "Upgrade")
    key = header(http, "Sec-WebSocket-Key")
    setheader(http, "Sec-WebSocket-Accept" => hashedkey(key))
    # If the client offered permessage-deflate (and the server allows it),
    # advertise acceptance with no_context_takeover on both sides — the
    # mode our implementation supports.
    pmd_accepted = permessage_deflate && _client_offers_pmd(http)
    if pmd_accepted
        setheader(http, "Sec-WebSocket-Extensions" =>
                  "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
    end
    startwrite(http)
    io = http.stream
    req = http.message

    # tune websocket tcp connection for performance : https://github.com/JuliaWeb/HTTP.jl/issues/1140
    @static if VERSION >= v"1.3"
        sock = tcpsocket(io)
        # I don't understand why uninitializd sockets can get here, but they can
        if sock.status ∉ (Base.StatusInit, Base.StatusUninit) && isopen(sock)
            Sockets.nagle(sock, nagle)
            Sockets.quickack(sock, quickack)
        end
    end

    ws = WebSocket(io, req, req.response; client=false, maxframesize, maxfragmentation)
    if pmd_accepted
        ws.pmd = PMDContext()
    end
    @debug "$(ws.id): WebSocket upgraded; connection established (pmd=$(ws.pmd !== nothing))"
    _pt = pong_timeout === nothing && ping_interval !== nothing ? 2 * Float64(ping_interval) : pong_timeout
    _start_heartbeat!(ws, ping_interval, _pt === nothing ? 0.0 : Float64(_pt))
    try
        f(ws)
    catch e
        if !isok(e)
            suppress_close_error || @error begin
                msg = current_exceptions_to_string()
                "$(ws.id): Unexpected websocket server error. $msg"
            end
        end
        if !isclosed(ws)
            if e isa WebSocketError && e.message isa CloseFrameBody
                close(ws, e.message)
            else
                close(ws, CloseFrameBody(1011, "Unexpected server websocket error"))
            end
        end
        if !isok(e)
            rethrow()
        end
    finally
        if !isclosed(ws)
            close(ws, CloseFrameBody(1000, ""))
        end
    end
end

# Sending messages
isbinary(x) = x isa AbstractVector{UInt8}
istext(x) = x isa AbstractString
opcode(x) = isbinary(x) ? BINARY : TEXT

# Coerce a `send` argument to an `AbstractVector{UInt8}` for `write_frame!`.
# `codeunits(::String)` returns a zero-copy `CodeUnits{UInt8, String}` view
# that satisfies `AbstractVector{UInt8}` and supports `copyto!`.
@inline _frame_payload(x::AbstractVector{UInt8}) = x
@inline _frame_payload(x::AbstractString) = codeunits(x)
@inline _frame_payload(x) = codeunits(string(x))

# Send one fully-compressed message in a single frame, with RSV1 set.
# RFC 7692 §7.2.1: compress the message with Z_SYNC_FLUSH and strip the
# trailing 0x00 0x00 0xff 0xff. The compressed bytes go in `ws.pmd.deflate_out`,
# which is reused across sends.
function _send_compressed_frame!(ws::WebSocket, op::OpCode, payload::AbstractVector{UInt8})
    pmd = ws.pmd::PMDContext
    plen = length(payload)
    nbytes = PMD.compress_message!(pmd.deflate, payload, plen, pmd.deflate_out)
    masked = ws.client
    total = header_len_for(nbytes, masked) + nbytes
    if length(ws.writebuffer) < total
        resize!(ws.writebuffer, total)
    end
    # Read compressed bytes from pmd.deflate_out into the WebSocket writebuffer
    # via _encode_frame!. Because `payload_data` is an AbstractVector{UInt8},
    # we pass a view over pmd.deflate_out.
    _encode_frame!(ws, ws.writebuffer, 0, true, op,
                   view(pmd.deflate_out, 1:nbytes); rsv1=true)
    n = emit_frame!(ws, total)
    s = ws.stats
    s.frames_sent += 1
    s.bytes_sent += plen          # uncompressed payload (app-level metric)
    s.compressed_bytes_sent += nbytes  # post-deflate wire bytes (ratio numerator)
    return n
end

"""
    send(ws::WebSocket, msg)

Send a message on a websocket connection. If `msg` is an `AbstractString`,
a TEXT websocket message will be sent; if `msg` is an `AbstractVector{UInt8}`,
a BINARY websocket message will be sent. Otherwise, `msg` should be an iterable
of either `AbstractString` or `AbstractVector{UInt8}`, and a fragmented message
will be sent, one frame for each iterated element.

Control frames can be sent by calling `ping(ws[, data])`, `pong(ws[, data])`,
or `close(ws[, body::WebSockets.CloseFrameBody])`. Calling `close` will initiate
the close sequence and close the underlying connection.
"""
function Sockets.send(ws::WebSocket, x)
    @debug "$(ws.id): Writing non-control message"
    @require !ws.writeclosed
    Base.@lock ws.writelock begin
        if isbinary(x) || istext(x)
            payload = _frame_payload(x)
            n = ws.pmd === nothing ?
                write_frame!(ws, true, opcode(x), payload) :
                _send_compressed_frame!(ws, opcode(x), payload)
            ws.stats.messages_sent += 1
            return n
        end
        # Fragmented send: x is an iterable of binary or text fragments.
        state = iterate(x)
        if state === nothing
            n = write_frame!(ws, true, TEXT, UInt8[])
            ws.stats.messages_sent += 1
            return n
        end
        @debug "$(ws.id): Writing fragmented message"
        item, st = state
        nextstate = iterate(x, st)
        first = true
        n = 0
        while true
            op = first ? opcode(item) : CONTINUATION
            n += write_frame!(ws, nextstate === nothing, op, _frame_payload(item))
            first = false
            nextstate === nothing && break
            item, st = nextstate
            nextstate = iterate(x, st)
        end
        ws.stats.messages_sent += 1
        return n
    end
end

"""
    send_batch(ws::WebSocket, msgs)

Send N separate websocket messages with **one** `unsafe_write` to the
underlying socket. `msgs` is any iterable of `AbstractString` (sent as
TEXT) and/or `AbstractVector{UInt8}` (sent as BINARY); each element
becomes its own FIN=1 frame, *not* one fragmented message.

Encodes all frames back-to-back into the WebSocket's preallocated
writebuffer, then issues a single write. With Nagle disabled (the
default for `WebSockets.open` / `upgrade`) this guarantees the entire
batch lands in one TCP segment when small enough — eliminating the
per-frame syscall and scheduler-roundtrip overhead that caps the
single-`send` loopback path at ~40k msg/s.

```julia
# Publish 100 small order updates with 1 syscall instead of 100:
send_batch(ws, [JSON.write(order) for order in orders])
```

Throws if any element isn't an AbstractString / AbstractVector{UInt8}.
Maintains the same multi-writer safety as `send` (writelock).

Returns the number of bytes written (header + payload, summed across
the batch).
"""
function send_batch(ws::WebSocket, msgs)
    @require !ws.writeclosed
    nmsgs = length(msgs)
    nmsgs == 0 && return 0
    Base.@lock ws.writelock begin
        masked = ws.client
        # First pass: total buffer size.
        total = 0
        @inbounds for m in msgs
            mlen = m isa AbstractString ? sizeof(m) :
                   m isa AbstractVector{UInt8} ? length(m) :
                   throw(ArgumentError("send_batch entries must be AbstractString or AbstractVector{UInt8}"))
            total += header_len_for(mlen, masked) + mlen
        end
        if length(ws.writebuffer) < total
            resize!(ws.writebuffer, total)
        end
        # Second pass: encode each frame back-to-back.
        offset = 0
        bytes_data = 0
        for m in msgs
            pload = _frame_payload(m)
            op = isbinary(m) ? BINARY : TEXT
            offset = _encode_frame!(ws, ws.writebuffer, offset, true, op, pload)
            bytes_data += length(pload)
        end
        n = emit_frame!(ws, total)
        s = ws.stats
        s.frames_sent += nmsgs
        s.messages_sent += nmsgs
        s.bytes_sent += bytes_data
        return n
    end
end

# control frames
"""
    ping(ws, data=[])

Send a PING control frame on a websocket connection. `data` is an optional
body to send with the message. PONG messages are automatically responded
to when a PING message is received by a websocket connection.
"""
function ping(ws::WebSocket, data=UInt8[])
    @require !ws.writeclosed
    @debug "$(ws.id): sending ping"
    Base.@lock ws.writelock begin
        n = write_frame!(ws, true, PING, _frame_payload(data))
        ws.stats.ping_count += 1
        return n
    end
end

"""
    pong(ws, data=[])

Send a PONG control frame on a websocket connection. `data` is an optional
body to send with the message. Note that PING messages are automatically
responded to internally by the websocket connection with a corresponding
PONG message, but in certain cases, a unidirectional PONG message can be
used as a one-way heartbeat.
"""
function pong(ws::WebSocket, data=UInt8[])
    @require !ws.writeclosed
    @debug "$(ws.id): sending pong"
    Base.@lock ws.writelock write_frame!(ws, true, PONG, _frame_payload(data))
end

"""
    close(ws, body::WebSockets.CloseFrameBody=nothing)

Initiate a close sequence on a websocket connection. `body` is an optional
`WebSockets.CloseFrameBody` with a status code and optional reason message.
If a CLOSE frame has already been received, then a responding CLOSE frame is sent
and the connection is closed. If a CLOSE frame hasn't already been received, the
CLOSE frame is sent and `receive` is attempted to receive the responding CLOSE
frame.
"""
function Base.close(ws::WebSocket, body::CloseFrameBody=CloseFrameBody(1000, ""))
    isclosed(ws) && return
    @debug "$(ws.id): Closing websocket"
    # Stop the heartbeat timer (if any) so it doesn't keep firing pings into
    # a half-closed socket.
    if ws.heartbeat !== nothing
        try; close(ws.heartbeat::Timer); catch; end
        ws.heartbeat = nothing
    end
    # Release zlib resources promptly (the finalizer will also do this,
    # but eagerly freeing keeps the libz state count predictable).
    if ws.pmd !== nothing
        _pmd_close!(ws.pmd::PMDContext)
        ws.pmd = nothing
    end
    ws.writeclosed = true
    msg = body.message
    payload_len = 2 + sizeof(msg)
    data = Vector{UInt8}(undef, payload_len)
    st = hton(UInt16(body.status))
    GC.@preserve data unsafe_store!(Ptr{UInt16}(pointer(data, 1)), st)
    if sizeof(msg) > 0
        GC.@preserve data msg unsafe_copyto!(pointer(data, 3),
                                             convert(Ptr{UInt8}, pointer(msg)),
                                             sizeof(msg))
    end
    try
        Base.@lock ws.writelock write_frame!(ws, true, CLOSE, data)
    catch
        # ignore thrown errors here because we're closing anyway
    end
    # if we're initiating the close, wait until we receive the
    # responding close frame or timeout
    if !ws.readclosed
        Timer(5) do t
            ws.readclosed = true
            !ws.client && isopen(ws.io) && close(ws.io)
        end
    end
    while !ws.readclosed
        try
            receive(ws)
        catch
            # ignore thrown errors here because we're closing anyway
            # but set readclosed so we don't keep trying to read
            ws.readclosed = true
        end
    end
    # we either recieved the responding CLOSE frame and readclosed was set
    # or there was an error/timeout reading it; in any case, readclosed should be closed now
    @assert ws.readclosed
    # if we're the server, it's our job to close the underlying socket
    !ws.client && isopen(ws.io) && close(ws.io)
    return
end

# Receiving messages

@noinline control_len_check(len) = len > 125 && throw(WebSocketError(CloseFrameBody(1002, "Invalid length for control frame")))
@noinline utf8check(x) = isvalid(x) || throw(WebSocketError(CloseFrameBody(1007, "Invalid UTF-8")))

# --- Fast receive path (used by `receive(ws)`) ---

# Read one frame header from `io`, using `hbuf` (>= WS_MAX_HEADER bytes) as
# scratch. Returns (flags, payload_len, mask_u32).
#
# Reads bytes directly into `hbuf` via `unsafe_read` and parses fields with
# `unsafe_load`. Avoids the per-call `Ref{T}` heap allocation that the generic
# `Base.read(io, T)` path uses for primitive types.
@inline function _read_header(io::IO, hbuf::Vector{UInt8})
    iocheck(io)
    GC.@preserve hbuf unsafe_read(io, pointer(hbuf), UInt(2))
    flags_u16 = GC.@preserve hbuf unsafe_load(Ptr{UInt16}(pointer(hbuf)))
    flags = FrameFlags(ntoh(flags_u16))
    if flags.len == 0x7E
        GC.@preserve hbuf unsafe_read(io, pointer(hbuf), UInt(2))
        len = UInt64(ntoh(GC.@preserve hbuf unsafe_load(Ptr{UInt16}(pointer(hbuf)))))
    elseif flags.len == 0x7F
        GC.@preserve hbuf unsafe_read(io, pointer(hbuf), UInt(8))
        len = ntoh(GC.@preserve hbuf unsafe_load(Ptr{UInt64}(pointer(hbuf))))
    else
        len = UInt64(flags.len)
    end
    mask_u32 = UInt32(0)
    if flags.masked
        GC.@preserve hbuf unsafe_read(io, pointer(hbuf), UInt(4))
        mask_u32 = GC.@preserve hbuf unsafe_load(Ptr{UInt32}(pointer(hbuf)))
    end
    return flags, len, mask_u32
end

# Read `n` bytes from `io` directly into `dest[offset+1 : offset+n]`,
# resizing `dest` if needed.
@inline function _read_into!(io::IO, dest::Vector{UInt8}, offset::Int, n::Int)
    n == 0 && return
    needed = offset + n
    if length(dest) < needed
        resize!(dest, needed)
    end
    GC.@preserve dest unsafe_read(io, pointer(dest, offset + 1), UInt(n))
    return
end

# Read one CONTROL frame (PING/PONG/CLOSE) payload into `dest[1:len]` and
# return the byte count. `dest` must have capacity >= 125 (RFC 6455 §5.5).
# Reusing a per-WebSocket scratch buffer here keeps inline control frames
# alloc-free on the receive hot path.
function _read_control_payload!(io::IO, dest::Vector{UInt8}, len::UInt64, masked::Bool, mask_u32::UInt32)
    control_len_check(len)
    n = Int(len)
    if n > 0
        GC.@preserve dest unsafe_read(io, pointer(dest), UInt(n))
        if masked
            mask!(dest, mask_u32, 1, n)
        end
    end
    return n
end

# Read one full data message (possibly fragmented) into ws.readbuffer.
# Sets ws.message_len to the assembled payload byte length and returns the
# data opcode (TEXT or BINARY). Handles inline control frames per RFC 6455 §5.4.
# Throws WebSocketError on protocol violation, CLOSE, or socket error.
function _recv_message!(ws::WebSocket)
    @require !ws.readclosed
    io = ws.io
    msg_opcode = CONTINUATION
    offset = 0
    hbuf = ws.headerbuf
    # `msg_compressed` is set when the first data frame of the message had
    # RSV1=1 (RFC 7692 §6: only the first frame of a message carries the
    # compression flag).
    msg_compressed = false
    while true
        # @inline at call site keeps the (flags, len, mask_u32) tuple unboxed.
        flags, len, mask_u32 = @inline _read_header(io, hbuf)
        # RSV1 is permitted only on the first frame of a compressed message
        # when permessage-deflate was negotiated. RSV2/RSV3 are never valid
        # without further extensions.
        if flags.rsv2 || flags.rsv3
            throw(WebSocketError(CloseFrameBody(1002, "Reserved bits set in frame")))
        end
        if flags.rsv1 && (ws.pmd === nothing || iscontrol(flags.opcode))
            throw(WebSocketError(CloseFrameBody(1002, "RSV1 set without permessage-deflate")))
        end
        op = flags.opcode
        if iscontrol(op)
            if !flags.final
                throw(WebSocketError(CloseFrameBody(1002, "Fragmented control frame")))
            end
            ctl = ws.ctlbuffer
            ctl_n = _read_control_payload!(io, ctl, len, flags.masked, mask_u32)
            if op == CLOSE
                ws.readclosed = true
                if ctl_n == 1
                    throw(WebSocketError(CloseFrameBody(1002, "Close frame cannot have body of length 1")))
                end
                status = ctl_n >= 2 ? Int((UInt16(ctl[1]) << 8) | ctl[2]) : 1005
                if ctl_n >= 2
                    validclosecheck(status)
                end
                # CLOSE body string only allocates here when there's a reason text;
                # not on the hot path (one CLOSE per connection lifetime).
                close_msg = if ctl_n > 2
                    GC.@preserve ctl unsafe_string(pointer(ctl) + 2, ctl_n - 2)
                else
                    ""
                end
                utf8check(close_msg)
                body = CloseFrameBody(status, close_msg)
                if !ws.writeclosed
                    close(ws, body)
                end
                throw(WebSocketError(body))
            elseif op == PING
                # Echo the PING body via a view — PONG payload is the same bytes.
                Base.@lock ws.writelock write_frame!(ws, true, PONG, view(ctl, 1:ctl_n))
                continue
            else # PONG
                # Track liveness; the heartbeat task reads `stats.last_pong`
                # to detect stale feeds.
                ws.stats.last_pong = time()
                ws.stats.pong_count += 1
                continue
            end
        end
        # Data frame
        if op == CONTINUATION
            if msg_opcode == CONTINUATION
                throw(WebSocketError(CloseFrameBody(1002, "Continuation frame cannot be the first frame in a message")))
            end
            # Continuation frames inherit the message's compression flag;
            # they must not carry RSV1 themselves.
            if flags.rsv1
                throw(WebSocketError(CloseFrameBody(1002, "RSV1 set on continuation frame")))
            end
        elseif op == TEXT || op == BINARY
            if msg_opcode != CONTINUATION
                throw(WebSocketError(CloseFrameBody(1002, "Received unfragmented frame while still processing fragmented frame")))
            end
            msg_opcode = op
            msg_compressed = flags.rsv1  # capture from first data frame
        else
            throw(WebSocketError(CloseFrameBody(1002, "Unknown opcode in data frame")))
        end
        if len > 0
            n = Int(len)
            # Compressed messages accumulate into a separate buffer so the
            # uncompressed `readbuffer` can be the destination of the inflate
            # output (no aliasing).
            target = msg_compressed ? ws.compressed_buffer : ws.readbuffer
            _read_into!(io, target, offset, n)
            if flags.masked
                mask!(target, mask_u32, offset + 1, n)
            end
            offset += n
        end
        ws.stats.frames_received += 1
        flags.final && break
    end
    # If the message was compressed, decompress now into readbuffer. The
    # final `offset` here is the count of compressed bytes; we update it
    # to the inflated byte count for downstream consumption.
    if msg_compressed
        pmd = ws.pmd::PMDContext
        ws.stats.compressed_bytes_received += offset
        offset = PMD.decompress_message!(pmd.inflate, ws.compressed_buffer, offset, pmd.inflate_out)
        # Copy decompressed bytes into readbuffer so downstream paths see the
        # same buffer regardless of whether compression was used.
        if length(ws.readbuffer) < offset
            resize!(ws.readbuffer, offset)
        end
        if offset > 0
            GC.@preserve ws unsafe_copyto!(pointer(ws.readbuffer),
                                            pointer(pmd.inflate_out), offset)
        end
    else
        # Uncompressed: wire bytes == app bytes.
        ws.stats.compressed_bytes_received += offset
    end
    ws.message_len = offset
    # Roll up message-level stats. Single histogram bump per logical message,
    # not per frame. `bytes_received` reflects the application's view of the
    # message (post-decompression), matching `bytes_sent` semantics.
    s = ws.stats
    s.messages_received += 1
    s.bytes_received += offset
    s.last_recv_time = time()
    _bump_recv_size!(s, offset)
    return msg_opcode
end

# Run `body()` with a wall-clock deadline. If `timeout` seconds elapse before
# `body` returns, the underlying TCP socket is closed so the blocking read
# unblocks and `_recv_message!` throws a WebSocketError(1006). This is the
# correct semantics for HFT stale-feed detection: a feed that has gone silent
# is presumed dead, and the application should reconnect rather than try to
# keep waiting on a half-open socket.
#
# `timeout::Nothing` means no deadline; `body()` is called directly.
@inline function _with_recv_deadline(body, ws::WebSocket, timeout)
    timeout === nothing && return body()
    timed_out = Ref(false)
    t = Timer(Float64(timeout)) do _
        timed_out[] = true
        try
            isopen(ws.io) && close(ws.io)
        catch
        end
    end
    try
        return body()
    catch e
        # If our timer fired, the underlying socket close surfaces as an
        # EOFError/IOError from inside unsafe_read. Translate it to the
        # protocol-level abnormal-closure error so callers can rely on a
        # single typed exception for stale-feed detection.
        if timed_out[]
            throw(WebSocketError(CloseFrameBody(1006, "Receive timed out after $(timeout)s")))
        end
        rethrow()
    finally
        close(t)
    end
end

"""
    receive(ws::WebSocket) -> Union{String, Vector{UInt8}}
    receive(ws::WebSocket; timeout::Real) -> Union{String, Vector{UInt8}}

Receive a message from a websocket connection. Returns a `String` if
the message was TEXT, or a `Vector{UInt8}` if the message was BINARY.
If control frames (ping or pong) are received, they are handled
automatically and a non-control message is waited for. If a CLOSE
message is received, it is responded to and a `WebSocketError` is thrown
with the `WebSockets.CloseFrameBody` as the error value. This error can
be checked with `WebSockets.isok(err)` to see if the closing was "normal"
or if an actual error occurred. For fragmented messages, the incoming
frames will continue to be read until the final fragment is received.
The bodies of each fragment are concatenated into the final message
returned by `receive`. Note that `WebSocket` objects can be iterated,
where each iteration yields a message until the connection is closed.

If `timeout` (in seconds) is passed and no message arrives within that
window, the underlying TCP socket is closed and a `WebSocketError`
with status 1006 ("abnormal closure") is thrown. This is the
appropriate semantic for HFT-style stale-feed detection: a silent
feed is presumed dead and should trigger a reconnect.
"""
function receive(ws::WebSocket; timeout::Union{Nothing,Real}=nothing)
    @debug "$(ws.id): Reading message"
    return _with_recv_deadline(ws, timeout) do
        op = _recv_message!(ws)
        n = ws.message_len
        buf = ws.readbuffer
        if op == TEXT
            s = GC.@preserve buf unsafe_string(pointer(buf), n)
            utf8check(s)
            return s
        else  # BINARY
            out = Vector{UInt8}(undef, n)
            if n > 0
                GC.@preserve out buf unsafe_copyto!(pointer(out), pointer(buf), n)
            end
            return out
        end
    end
end

"""
    receive(f, ws::WebSocket; validate_utf8=false)

Zero-copy variant of [`receive`](@ref): reads one full (possibly
fragmented) non-control message into the WebSocket's internal buffer
and calls `f(payload, opcode)`, where `payload` is a transient
`SubArray{UInt8}` view of the bytes (valid only until the next
`receive` / `send` call on `ws`) and `opcode` is `WebSockets.TEXT` or
`WebSockets.BINARY`.

This avoids the per-message allocation that `receive(ws)` does to
materialize the returned `String` or `Vector{UInt8}`. If the caller
needs to retain the bytes beyond the call, they must `copy(payload)`
or `String(copy(payload))`.

UTF-8 validation is **not** performed by default. Pass
`validate_utf8=true` to opt in for TEXT messages. The default-off
behavior is intended for HFT pipelines where the upstream payload is
known to be well-formed (and where a one-shot UTF-8 scan over every
message would dominate hot-path cost).

Whatever `f` returns is returned from `receive`.

```julia
WebSockets.open(url) do ws
    while !WebSockets.isclosed(ws)
        receive(ws) do bytes, op
            # parse `bytes` directly (e.g. via simdjson / msgpack / your
            # own protocol) - no allocation occurs here from HTTP.jl's side.
        end
    end
end
```
"""
function receive(f::Function, ws::WebSocket; validate_utf8::Bool=false,
                 timeout::Union{Nothing,Real}=nothing)
    @debug "$(ws.id): Reading message (zero-copy)"
    return _with_recv_deadline(ws, timeout) do
        op = _recv_message!(ws)
        n = ws.message_len
        buf = ws.readbuffer
        v = view(buf, 1:n)
        if validate_utf8 && op == TEXT
            # `isvalid(::AbstractString)` does UTF-8 validation. We materialize
            # the bytes into a String once for the check; this still skips the
            # owned-payload alloc that `receive(ws)` makes for the return value.
            isvalid(String(copy(v))) || throw(WebSocketError(CloseFrameBody(1007, "Invalid UTF-8")))
        end
        return f(v, op)
    end
end

"""
    iterate(ws)

Continuously call `receive(ws)` on a `WebSocket` connection, with
each iteration yielding a message until the connection is closed.
E.g.
```julia
for msg in ws
    # do something with msg
end
```
"""
function Base.iterate(ws::WebSocket, st=nothing)
    isclosed(ws) && return nothing
    try
        return receive(ws), nothing
    catch e
        isok(e) && return nothing
        rethrow(e)
    end
end

end # module WebSockets
