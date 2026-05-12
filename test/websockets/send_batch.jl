# Tests for send_batch: N messages, one unsafe_write, FIN=1 per frame.

using Test
using HTTP
using HTTP.WebSockets

@testset "WebSocket send_batch" begin

    @testset "N text messages received as N separate messages" begin
        ch = Channel{Vector{String}}(1)
        srv = WebSockets.listen!("127.0.0.1", 8230; suppress_close_error=true) do ws
            got = String[]
            try
                while !WebSockets.isclosed(ws) && length(got) < 5
                    push!(got, receive(ws))
                end
            catch
            end
            put!(ch, got)
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8230") do ws
                send_batch(ws, ["a", "bb", "ccc", "dddd", "eeeee"])
                @test stats(ws).messages_sent == 5
                @test stats(ws).frames_sent == 5
                @test stats(ws).bytes_sent == 1 + 2 + 3 + 4 + 5
            end
            got = take!(ch)
            @test got == ["a", "bb", "ccc", "dddd", "eeeee"]
        finally
            close(srv)
        end
    end

    @testset "mixed text + binary entries" begin
        ch = Channel{Vector{Any}}(1)
        srv = WebSockets.listen!("127.0.0.1", 8231; suppress_close_error=true) do ws
            got = Any[]
            try
                while !WebSockets.isclosed(ws) && length(got) < 3
                    push!(got, receive(ws))
                end
            catch
            end
            put!(ch, got)
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8231") do ws
                send_batch(ws, Any["hello", UInt8[0xAA, 0xBB], "tail"])
            end
            got = take!(ch)
            @test got[1] == "hello"
            @test got[2] == UInt8[0xAA, 0xBB]
            @test got[3] == "tail"
        finally
            close(srv)
        end
    end

    @testset "non-string/bytes entry throws ArgumentError" begin
        srv = WebSockets.listen!("127.0.0.1", 8232; suppress_close_error=true) do ws
            try; receive(ws); catch; end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8232") do ws
                @test_throws ArgumentError send_batch(ws, Any[42, "ok"])
            end
        finally
            close(srv)
        end
    end

    @testset "empty batch is a no-op" begin
        srv = WebSockets.listen!("127.0.0.1", 8233; suppress_close_error=true) do ws
            try; receive(ws; timeout=0.5); catch; end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8233") do ws
                @test send_batch(ws, String[]) == 0
                @test stats(ws).messages_sent == 0
            end
        finally
            close(srv)
        end
    end

end
