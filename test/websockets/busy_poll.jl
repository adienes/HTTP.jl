# Tests for the busy_poll_us receive fast path.
#
# When `busy_poll_us > 0` and the underlying transport is a plain TCPSocket,
# the receive path spins on `recv(fd, ..., MSG_DONTWAIT)` directly against
# the kernel for up to `busy_poll_us` microseconds before falling back to
# libuv's blocking read. Trades CPU for tail-latency wins.

using Test
using HTTP
using HTTP.WebSockets
using Sockets

@testset "busy_poll_us receive path" begin

    @testset "default (0) preserves existing receive semantics" begin
        # No busy poll, no surprises — same path master/hft-optim took before.
        ch = Channel{String}(1)
        srv = WebSockets.listen!("127.0.0.1", 8250; suppress_close_error=true) do ws
            put!(ch, receive(ws))
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8250") do ws
                @test ws.busy_poll_ns == 0
                send(ws, "no spin")
            end
            @test take!(ch) == "no spin"
        finally
            close(srv)
        end
    end

    @testset "busy_poll_us=200 round-trips correctly (small + large messages)" begin
        # The receive path swaps in raw recv() reads for plain TCP — the
        # frame parse must still correctly handle short bodies, long bodies,
        # masked-from-client frames, and the inline CLOSE handshake at the
        # end of the connection.
        ch = Channel{Any}(8)
        srv = WebSockets.listen!("127.0.0.1", 8251; suppress_close_error=true) do ws
            # Server echoes everything until client closes.
            try
                for msg in ws
                    put!(ch, msg)
                    send(ws, msg)
                end
            catch
            end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8251"; busy_poll_us=200) do ws
                @test ws.busy_poll_ns == 200_000
                # Small text
                send(ws, "hello")
                @test receive(ws) == "hello"
                # Larger text (>125 bytes, exercises the 16-bit ext-len branch
                # on incoming masked frames from server-side write_frame!).
                msg = repeat("x", 300)
                send(ws, msg)
                @test receive(ws) == msg
                # Even larger (forces 16-bit ext-len, exercises payload spin)
                msg = repeat("y", 50_000)
                send(ws, msg)
                @test receive(ws) == msg
                # Binary frame
                bin = collect(UInt8(i & 0xff) for i in 1:128)
                send(ws, bin)
                @test receive(ws) == bin
            end
        finally
            close(srv)
        end
    end

    @testset "busy_poll on receive(f, ws) zero-copy callback works" begin
        srv = WebSockets.listen!("127.0.0.1", 8252; suppress_close_error=true) do ws
            send(ws, "callback")
            try; receive(ws); catch; end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8252"; busy_poll_us=100) do ws
                got = receive(ws) do bytes, op
                    @test op == WebSockets.TEXT
                    String(copy(bytes))
                end
                @test got == "callback"
            end
        finally
            close(srv)
        end
    end

    @testset "busy_poll sustains a high-rate ping-pong without dropping frames" begin
        # Stress test: 2000 round-trips through the busy-poll receive path.
        # The combination of raw recv() + libuv fallback must correctly
        # preserve frame boundaries and byte order across many iterations.
        srv = WebSockets.listen!("127.0.0.1", 8253; suppress_close_error=true) do ws
            for msg in ws
                send(ws, msg)
            end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8253"; busy_poll_us=200) do ws
                payload = collect(UInt8(i & 0xff) for i in 1:64)
                for i in 1:2000
                    send(ws, payload)
                    received = receive(ws)
                    @test received == payload
                end
            end
        finally
            close(srv)
        end
    end

end
