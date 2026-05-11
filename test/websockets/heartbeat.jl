# Tests for the optional WebSocket heartbeat (ping_interval / pong_timeout).
# When set, the client / server fires PINGs at the interval and tears down the
# connection if no PONG has arrived within pong_timeout. Counts are exposed
# via `ws.ping_count` / `ws.pong_count` for observability.

using Test
using HTTP
using HTTP.WebSockets
using Sockets

@testset "WebSocket heartbeat" begin

    @testset "client ping_interval emits PINGs; server auto-PONG keeps it alive" begin
        # Server's default receive loop auto-replies to incoming PINGs.
        srvping = Channel{Nothing}(1)
        ready = Channel{Nothing}(1)
        srv = WebSockets.listen!("127.0.0.1", 8210; suppress_close_error=true) do ws
            put!(ready, nothing)
            try
                while !WebSockets.isclosed(ws)
                    try; receive(ws); catch; break; end
                end
            catch
            end
            put!(srvping, nothing)
        end
        try
            sleep(0.2)
            # ping every 100 ms; allow up to 1 s before tearing down.
            # We need to be actively `receive`-ing on the client so the
            # PONGs the server sends get drained (and bump pong_count).
            # Realistic HFT subscriber usage: app's main loop is receive.
            WebSockets.open("ws://127.0.0.1:8210"; ping_interval=0.1, pong_timeout=1.0) do ws
                take!(ready)
                reader = @async begin
                    try
                        while !WebSockets.isclosed(ws)
                            receive(ws)
                        end
                    catch
                    end
                end
                sleep(0.5)
                @test ws.ping_count >= 3
                @test ws.pong_count >= 3
                @test !WebSockets.isclosed(ws)
                # close() will cancel the heartbeat + kill the reader task.
            end
            take!(srvping)
        finally
            close(srv)
        end
    end

    @testset "missed PONGs tear down the connection" begin
        # Server completes the handshake then *never* services its receive
        # loop, so it never auto-replies to PINGs.
        srvready = Channel{Nothing}(1)
        srv = WebSockets.listen!("127.0.0.1", 8211; suppress_close_error=true) do ws
            put!(srvready, nothing)
            # Block here on a long sleep — do NOT call receive, so the
            # client's PINGs go unanswered.
            sleep(10.0)
        end
        try
            sleep(0.2)
            client_alive_at_end = Ref(true)
            WebSockets.open("ws://127.0.0.1:8211";
                            ping_interval=0.1, pong_timeout=0.3,
                            suppress_close_error=true) do ws
                take!(srvready)
                # Wait long enough for ping_interval to fire and the
                # pong_timeout window to elapse with no responses.
                t0 = time()
                while !WebSockets.isclosed(ws) && time() - t0 < 2.0
                    try
                        receive(ws; timeout=0.2)
                    catch
                        break
                    end
                end
                client_alive_at_end[] = !WebSockets.isclosed(ws) && isopen(ws.io)
            end
            # Connection should have been torn down by the heartbeat.
            @test client_alive_at_end[] == false
        finally
            close(srv)
        end
    end

end
