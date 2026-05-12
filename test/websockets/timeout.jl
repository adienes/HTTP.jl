# Tests for `receive(ws; timeout=...)` and `receive(f, ws; timeout=...)`.
# The deadline closes the underlying socket on expiry, which surfaces as
# `WebSocketError(CloseFrameBody(1006, ...))`. Used by HFT consumers for
# stale-feed detection.

using Test
using HTTP
using HTTP.WebSockets
using Sockets

@testset "WebSocket receive timeout" begin
    @testset "data arrives in time" begin
        ch = Channel{String}(1)
        srv = WebSockets.listen!("127.0.0.1", 8200; suppress_close_error=true) do ws
            sleep(0.3)
            send(ws, "ontime")
            put!(ch, "ok")
            try; receive(ws; timeout=2.0); catch; end
        end
        try
            sleep(0.3)
            WebSockets.open("ws://127.0.0.1:8200") do ws
                msg = receive(ws; timeout=2.0)
                @test msg == "ontime"
            end
            @test take!(ch) == "ok"
        finally
            close(srv)
        end
    end

    @testset "timeout fires, typed WebSocketError" begin
        chstart = Channel{Nothing}(1)
        chstop = Channel{Nothing}(1)
        srv = WebSockets.listen!("127.0.0.1", 8201; suppress_close_error=true) do ws
            put!(chstart, nothing)
            try; receive(ws; timeout=5.0); catch; end
            put!(chstop, nothing)
        end
        try
            sleep(0.3)
            threw = Ref(false)
            elapsed = Ref(0.0)
            etype = Ref{Any}(nothing)
            WebSockets.open("ws://127.0.0.1:8201"; suppress_close_error=true) do ws
                take!(chstart)
                t0 = time()
                try
                    receive(ws; timeout=0.3)
                catch e
                    threw[] = true
                    elapsed[] = time() - t0
                    etype[] = e
                end
            end
            @test threw[]
            @test elapsed[] < 1.0  # fired well within budget
            @test etype[] isa WebSockets.WebSocketError
            take!(chstop)
        finally
            close(srv)
        end
    end

    @testset "zero-copy receive(f, ws; timeout=...) succeeds" begin
        srv = WebSockets.listen!("127.0.0.1", 8202; suppress_close_error=true) do ws
            sleep(0.2)
            send(ws, b"\x01\x02\x03")
            try; receive(ws; timeout=2.0); catch; end
        end
        try
            sleep(0.3)
            WebSockets.open("ws://127.0.0.1:8202") do ws
                n = receive(ws; timeout=2.0) do bytes, op
                    length(bytes)
                end
                @test n == 3
            end
        finally
            close(srv)
        end
    end
end
