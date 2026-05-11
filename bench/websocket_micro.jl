#=
Microbenchmarks for HTTP.WebSockets hot paths.

Run with the HTTP.jl project active. Compares mask!, frame encode (writeframe
or write_frame!, depending on branch), and the per-frame RNG cost.

    julia --project bench/websocket_micro.jl

The script works on both master and hft-optim; methods that don't exist on a
branch are skipped.
=#

using Printf
using HTTP
using HTTP.WebSockets
using BenchmarkTools
using Random
using Sockets

const WS = HTTP.WebSockets

println("# WebSocket microbenchmarks")
println("# branch: ", strip(read(`git -C $(pkgdir(HTTP)) rev-parse --abbrev-ref HEAD`, String)))
println("# julia: ", VERSION)
println()

# ---- mask! ----
println("## mask! (XOR a byte buffer with a 32-bit key)")
# `mask!` accepts either a `UInt32` key directly (current API) or a `Mask`
# wrapper (older API, removed in the cleanup commit). Use whichever the
# branch exposes so the bench runs unmodified across the whole history.
const _MASK_ARG = isdefined(WS, :Mask) ? WS.Mask(rand(UInt32)) : rand(UInt32)
for n in (32, 256, 1024, 16384, 1_048_576)
    buf = rand(UInt8, n)
    b = @benchmark WS.mask!($buf, $(_MASK_ARG)) samples=1000 evals=10
    t_ns = minimum(b).time
    gbps = (n / (t_ns * 1e-9)) / 1e9
    @printf "  %10d bytes: %8.1f ns  (%.2f GB/s)\n" n t_ns gbps
end

# A trivial sink so we can exercise the encode path without touching a socket.
mutable struct DiscardSink <: IO end
Base.unsafe_write(::DiscardSink, ::Ptr{UInt8}, n::UInt) = Int(n)
Base.write(s::DiscardSink, x::AbstractVector{UInt8}) = length(x)
Base.isopen(::DiscardSink) = true

mutable struct DiscardConnShim
    io::DiscardSink
end
Base.unsafe_write(c::DiscardConnShim, p::Ptr{UInt8}, n::UInt) = unsafe_write(c.io, p, n)
Base.isopen(::DiscardConnShim) = true

# Mini-WebSocket compatible with the internal write_frame! API (post-refactor).
mutable struct MiniWS
    io::DiscardConnShim
    client::Bool
    writebuffer::Vector{UInt8}
    writelock::ReentrantLock
    rng::Xoshiro
end
MiniWS(; client=true) =
    MiniWS(DiscardConnShim(DiscardSink()), client, UInt8[], ReentrantLock(),
           Xoshiro(0x1, 0x2, 0x3, 0x4))

if isdefined(WS, :write_frame!)
    println()
    println("## write_frame! into discard sink (new fast path)")
    for client in (true, false), n in (32, 128, 1024, 16384)
        ws = MiniWS(; client)
        msg = rand(UInt8, n)
        # warm up to size the writebuffer
        for _ in 1:5; WS.write_frame!(ws, true, WS.BINARY, msg); end
        b = @benchmark WS.write_frame!($ws, true, $(WS.BINARY), $msg) samples=2000 evals=5
        t = minimum(b)
        @printf "  client=%-5s len=%-6d  %7.1f ns  alloc=%d (%d bytes)\n" client n t.time t.allocs t.memory
    end
end

# ---- Frame()+writeframe path (only on commits before the cleanup) ----
if isdefined(WS, :Frame) && isdefined(WS, :writeframe)
    println()
    println("## Frame(...)+writeframe(io, frame) -> IOBuffer  (legacy path)")

    struct StreamShim <: IO
        io::IOBuffer
    end
    Base.unsafe_write(s::StreamShim, p::Ptr{UInt8}, n::UInt) = unsafe_write(s.io, p, n)
    Base.write(s::StreamShim, x::AbstractVector{UInt8}) = write(s.io, x)
    Base.isopen(::StreamShim) = true

    for client in (true, false), n in (32, 128, 1024, 16384)
        msg_orig = rand(UInt8, n)
        s = StreamShim(IOBuffer())
        bench = function ()
            truncate(s.io, 0); seekstart(s.io)
            msg = copy(msg_orig)  # writeframe mutates payload when client
            WS.writeframe(s, WS.Frame(true, WS.BINARY, client, msg))
        end
        b = @benchmark $bench() samples=2000 evals=5
        t = minimum(b)
        @printf "  client=%-5s len=%-6d  %7.1f ns  alloc=%d (%d bytes)\n" client n t.time t.allocs t.memory
    end
end
