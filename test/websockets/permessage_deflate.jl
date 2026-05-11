# Tests for permessage-deflate (RFC 7692) negotiation + transmission.

using Test
using HTTP
using HTTP.WebSockets

@testset "WebSocket permessage-deflate" begin

    @testset "client opts in, server accepts, round trip" begin
        ch = Channel{String}(1)
        srv = WebSockets.listen!("127.0.0.1", 8240; suppress_close_error=true) do ws
            @test ws.pmd !== nothing  # server enabled compression
            msg = receive(ws)
            put!(ch, msg)
            send(ws, "echo: $msg")
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8240"; permessage_deflate=true) do ws
                @test ws.pmd !== nothing  # client confirmed it's active
                send(ws, "hello compressed world")
                reply = receive(ws)
                @test reply == "echo: hello compressed world"
            end
            @test take!(ch) == "hello compressed world"
        finally
            close(srv)
        end
    end

    @testset "binary payload round trip" begin
        ch = Channel{Vector{UInt8}}(1)
        srv = WebSockets.listen!("127.0.0.1", 8241; suppress_close_error=true) do ws
            msg = receive(ws)
            put!(ch, msg)
        end
        try
            sleep(0.2)
            data = collect(0x00:0xFF)  # 256-byte payload
            WebSockets.open("ws://127.0.0.1:8241"; permessage_deflate=true) do ws
                send(ws, data)
            end
            @test take!(ch) == data
        finally
            close(srv)
        end
    end

    @testset "client without permessage_deflate doesn't negotiate" begin
        ch = Channel{Bool}(1)
        srv = WebSockets.listen!("127.0.0.1", 8242; suppress_close_error=true) do ws
            put!(ch, ws.pmd !== nothing)
            try; receive(ws); catch; end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8242") do ws
                @test ws.pmd === nothing
                send(ws, "uncompressed")
            end
            @test take!(ch) == false  # server side also uncompressed
        finally
            close(srv)
        end
    end

    @testset "highly compressible message saves bytes on the wire" begin
        srv = WebSockets.listen!("127.0.0.1", 8243; suppress_close_error=true) do ws
            msg = receive(ws)
            @test sizeof(msg) == 10_000
            s = stats(ws)
            # 'a' x 10000 inflates from ~30 wire bytes.
            @test s.bytes_received == 10_000
            @test s.compressed_bytes_received < 200
            try; receive(ws); catch; end
        end
        try
            sleep(0.2)
            payload = repeat("a", 10_000)
            WebSockets.open("ws://127.0.0.1:8243"; permessage_deflate=true) do ws
                send(ws, payload)
                s = stats(ws)
                @test s.bytes_sent == 10_000
                @test s.compressed_bytes_sent < 200
            end
        finally
            close(srv)
        end
    end

end
