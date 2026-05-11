#=
Loopback (client <-> server) websocket benchmark.

Measures, for a few message sizes:
  * throughput (msgs / sec) for one-way blast
  * allocations per send on the client
  * end-to-end latency p50 / p99 for ping-pong

Works on master and hft-optim. The zero-copy receive(f, ws) branch is exercised
only when present.

    julia --project bench/websocket_loopback.jl
=#

using Printf
using HTTP
using HTTP.WebSockets
using Sockets
using Statistics
using Random

const WS = HTTP.WebSockets

println("# WebSocket loopback benchmark")
println("# branch: ", strip(read(`git -C $(pkgdir(HTTP)) rev-parse --abbrev-ref HEAD`, String)))
println("# julia: ", VERSION)
println()

# Pick a port range above 30000 to reduce collisions.
const PORT_BASE = 33000

function bench_oneway_blast(payload::Vector{UInt8}, N::Int; port::Int,
                            batch_size::Int=1)
    received_count = Threads.Atomic{Int}(0)
    server_done = Channel{Nothing}(1)
    srv = WS.listen!("127.0.0.1", port; suppress_close_error=true) do ws
        if isdefined(WS, :receive) && hasmethod(WS.receive, Tuple{Function, WebSocket})
            try
                while true
                    WS.receive(ws) do bytes, op
                        Threads.atomic_add!(received_count, 1)
                    end
                    received_count[] >= N && break
                end
            catch
            end
        else
            try
                for _ in ws
                    Threads.atomic_add!(received_count, 1)
                    received_count[] >= N && break
                end
            catch
            end
        end
        put!(server_done, nothing)
    end
    sleep(0.5)
    t = 0.0
    allocd = 0
    gc_count = 0
    use_batch = batch_size > 1 && isdefined(WS, :send_batch)
    WS.open("ws://127.0.0.1:$port") do ws
        batch = fill(payload, batch_size)  # all entries are the same Vector ref
        # warm
        if use_batch
            for _ in 1:cld(1000, batch_size); WS.send_batch(ws, batch); end
        else
            for _ in 1:1000; send(ws, payload); end
        end
        GC.gc()
        n0 = Base.gc_num()
        t0 = time()
        if use_batch
            nbatches = cld(N, batch_size)
            for _ in 1:nbatches; WS.send_batch(ws, batch); end
        else
            for _ in 1:N; send(ws, payload); end
        end
        t = time() - t0
        n1 = Base.gc_num()
        allocd = (n1.poolalloc + n1.bigalloc) - (n0.poolalloc + n0.bigalloc)
        gc_count = n1.total_time - n0.total_time
    end
    # wait for server to drain
    try; take!(server_done); catch; end
    close(srv)
    sent = use_batch ? cld(N, batch_size) * batch_size : N
    return (t=t, allocs_per_msg=allocd / sent, msgs_per_sec=sent / t)
end

function bench_pingpong(payload::Vector{UInt8}, N::Int; port::Int)
    # Server echoes
    srv = WS.listen!("127.0.0.1", port; suppress_close_error=true) do ws
        try
            for msg in ws
                send(ws, msg)
            end
        catch
        end
    end
    sleep(0.5)
    latencies_ns = Vector{Float64}(undef, N)
    WS.open("ws://127.0.0.1:$port") do ws
        # warm
        for _ in 1:1000
            send(ws, payload)
            receive(ws)
        end
        for i in 1:N
            t0 = time_ns()
            send(ws, payload)
            receive(ws)
            latencies_ns[i] = float(time_ns() - t0)
        end
    end
    close(srv)
    return latencies_ns
end

# Receive-side blast: server sends N frames as fast as it can, client either
# materializes via `receive(ws)` or uses zero-copy `receive(f, ws)`.
function bench_recv(payload::Vector{UInt8}, N::Int; port::Int, zero_copy::Bool)
    srv = WS.listen!("127.0.0.1", port; suppress_close_error=true) do ws
        try
            for _ in 1:N
                send(ws, payload)
            end
            # keep socket alive until the client has drained
            try; receive(ws); catch; end
        catch
        end
    end
    sleep(0.5)
    t = 0.0
    allocd = 0
    bytes_allocd = 0
    WS.open("ws://127.0.0.1:$port") do ws
        # warm-up: pull the first 1000 frames so JIT specializations are done
        if zero_copy
            for _ in 1:1000
                receive(ws) do bytes, op
                    nothing
                end
            end
        else
            for _ in 1:1000
                receive(ws)
            end
        end
        GC.gc()
        n0 = Base.gc_num()
        t0 = time()
        if zero_copy
            for _ in 1:(N - 1000)
                receive(ws) do bytes, op
                    nothing  # do absolutely nothing — measure HTTP.jl overhead only
                end
            end
        else
            for _ in 1:(N - 1000)
                receive(ws)
            end
        end
        t = time() - t0
        n1 = Base.gc_num()
        allocd = (n1.poolalloc + n1.bigalloc) - (n0.poolalloc + n0.bigalloc)
        bytes_allocd = n1.allocd - n0.allocd
        send(ws, UInt8[])  # signal end
    end
    close(srv)
    n_measured = N - 1000
    return (t=t, allocs_per_msg=allocd / n_measured,
            bytes_per_msg=bytes_allocd / n_measured,
            msgs_per_sec=n_measured / t)
end

# ---------- run ----------

# Distinct ports per size/section, kept within UInt16.
const SIZES = (16, 64, 512, 4096)
size_offset(sz) = sz == 16 ? 1 : sz == 64 ? 2 : sz == 512 ? 3 : 4

println("## one-way blast (client -> server), N=50_000")
for sz in SIZES
    payload = rand(UInt8, sz)
    r = bench_oneway_blast(payload, 50_000; port=PORT_BASE + size_offset(sz))
    @printf "  payload=%-6d  %7.1f k msg/s  %5.2f allocs/send  (%.2f s)\n" sz (r.msgs_per_sec/1000) r.allocs_per_msg r.t
end

if isdefined(WS, :send_batch)
    println()
    println("## one-way blast (client -> server) via send_batch, N=50_000")
    for sz in SIZES, b in (8, 64)
        payload = rand(UInt8, sz)
        r = bench_oneway_blast(payload, 50_000;
                                port=PORT_BASE + 400 + 10*size_offset(sz) + b,
                                batch_size=b)
        @printf "  payload=%-6d batch=%-4d  %7.1f k msg/s  %5.2f allocs/send  (%.2f s)\n" sz b (r.msgs_per_sec/1000) r.allocs_per_msg r.t
    end
end

println()
println("## one-way blast (server -> client), receive(ws), N=50_000")
for sz in SIZES
    payload = rand(UInt8, sz)
    r = bench_recv(payload, 50_000; port=PORT_BASE + 100 + size_offset(sz), zero_copy=false)
    @printf "  payload=%-6d  %7.1f k msg/s  %5.2f allocs/recv  %6.1f bytes/recv\n" sz (r.msgs_per_sec/1000) r.allocs_per_msg r.bytes_per_msg
end

if hasmethod(receive, Tuple{Function, WebSocket})
    println()
    println("## one-way blast (server -> client), receive(f, ws) [zero-copy], N=50_000")
    for sz in SIZES
        payload = rand(UInt8, sz)
        r = bench_recv(payload, 50_000; port=PORT_BASE + 200 + size_offset(sz), zero_copy=true)
        @printf "  payload=%-6d  %7.1f k msg/s  %5.2f allocs/recv  %6.1f bytes/recv\n" sz (r.msgs_per_sec/1000) r.allocs_per_msg r.bytes_per_msg
    end
end

println()
println("## ping-pong RTT (client send -> server echo -> client recv), N=20_000")
for sz in SIZES
    payload = rand(UInt8, sz)
    lat = bench_pingpong(payload, 20_000; port=PORT_BASE + 300 + size_offset(sz))
    p50 = quantile(lat, 0.50) / 1000   # µs
    p99 = quantile(lat, 0.99) / 1000   # µs
    p999 = quantile(lat, 0.999) / 1000 # µs
    @printf "  payload=%-6d  p50=%6.1f µs  p99=%7.1f µs  p99.9=%8.1f µs\n" sz p50 p99 p999
end
