# Tests for per-WebSocket stats / metrics exposed via `stats(ws)`.

using Test
using HTTP
using HTTP.WebSockets

@testset "WebSocket stats" begin

    @testset "messages_sent / messages_received increment correctly" begin
        ch_msg_count = Channel{Int}(1)
        ch_recv = Channel{Int}(1)
        srv = WebSockets.listen!("127.0.0.1", 8220; suppress_close_error=true) do ws
            n = 0
            for _ in ws
                n += 1
            end
            put!(ch_msg_count, n)
            put!(ch_recv, stats(ws).messages_received)
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8220") do ws
                @test stats(ws).messages_sent == 0
                send(ws, "first")
                send(ws, "second")
                send(ws, UInt8[0x01, 0x02, 0x03])
                @test stats(ws).messages_sent == 3
                @test stats(ws).bytes_sent == sizeof("first") + sizeof("second") + 3
                @test stats(ws).frames_sent == 3
            end
            @test take!(ch_msg_count) == 3
            @test take!(ch_recv) == 3
        finally
            close(srv)
        end
    end

    @testset "recv_size_buckets" begin
        srv = WebSockets.listen!("127.0.0.1", 8221; suppress_close_error=true) do ws
            # Send messages targeting each bucket: <64, 64-, 256-, 1024-, 4096-, >=16384
            send(ws, "x"^10)
            send(ws, "x"^100)
            send(ws, "x"^500)
            send(ws, "x"^2000)
            send(ws, "x"^8000)
            send(ws, "x"^20000)
            try; receive(ws); catch; end  # wait for client to close
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8221") do ws
                for _ in 1:6
                    receive(ws)
                end
                b = stats(ws).recv_size_buckets
                @test b == (1, 1, 1, 1, 1, 1)
            end
        finally
            close(srv)
        end
    end

    @testset "last_recv_time updates" begin
        srv = WebSockets.listen!("127.0.0.1", 8222; suppress_close_error=true) do ws
            send(ws, "ok")
            try; receive(ws); catch; end
        end
        try
            sleep(0.2)
            WebSockets.open("ws://127.0.0.1:8222") do ws
                @test stats(ws).last_recv_time == 0.0
                receive(ws)
                @test stats(ws).last_recv_time > 0.0
                @test time() - stats(ws).last_recv_time < 2.0
            end
        finally
            close(srv)
        end
    end

end
