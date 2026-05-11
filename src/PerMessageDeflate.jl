"""
    PerMessageDeflate

Minimal RFC 7692 (permessage-deflate) support: raw deflate / inflate
contexts that compress/decompress one WebSocket data message at a time,
with the sync-flush tail handling the spec requires.

We bind libz directly (via `Zlib_jll`) rather than going through
`CodecZlib` because RFC 7692 mandates `Z_SYNC_FLUSH` and the
per-message strip/append of the trailing `0x00 0x00 0xff 0xff` block —
behavior that the higher-level codec wrappers don't expose.

Configured for "no context takeover" mode (the simpler subset): each
message is compressed/decompressed in isolation by calling
`deflateReset` / `inflateReset` between messages. Sliding-window
sharing across messages (the default if you don't negotiate
`client_no_context_takeover` / `server_no_context_takeover`) is not
supported, so the client always negotiates both no-takeover parameters
in the handshake.

This module is internal — public surface lives in WebSockets.jl.
"""
module PerMessageDeflate

using Zlib_jll: libz

# z_stream struct layout (libz 1.2.x / 1.3.x). 88 bytes on 64-bit.
# Field order and types follow zlib.h: next_in is a pointer, avail_in
# is uInt (Cuint), total_in is uLong (Culong), etc. Padding makes the
# struct alignment-safe under both LP64 and LLP64.
mutable struct ZStream
    next_in::Ptr{UInt8}
    avail_in::Cuint
    total_in::Culong
    next_out::Ptr{UInt8}
    avail_out::Cuint
    total_out::Culong
    msg::Ptr{Cchar}
    state::Ptr{Cvoid}
    zalloc::Ptr{Cvoid}
    zfree::Ptr{Cvoid}
    opaque::Ptr{Cvoid}
    data_type::Cint
    adler::Culong
    reserved::Culong
end
ZStream() = ZStream(C_NULL, 0, 0, C_NULL, 0, 0, C_NULL, C_NULL, C_NULL, C_NULL, C_NULL, 0, 0, 0)

# Flush constants
const Z_NO_FLUSH      = Cint(0)
const Z_SYNC_FLUSH    = Cint(2)
const Z_FINISH        = Cint(4)
# Return codes
const Z_OK            = Cint(0)
const Z_STREAM_END    = Cint(1)
const Z_BUF_ERROR     = Cint(-5)
# Defaults
const Z_DEFAULT_COMPRESSION = Cint(-1)
const Z_DEFLATED            = Cint(8)
const Z_DEFAULT_STRATEGY    = Cint(0)

zlib_version() = unsafe_string(ccall((:zlibVersion, libz), Cstring, ()))

function _check(ret::Cint, ctx::String)
    if ret < 0 && ret != Z_BUF_ERROR
        error("zlib $ctx returned $ret")
    end
    return ret
end

function deflate_init!(zs::ZStream; level::Integer=Z_DEFAULT_COMPRESSION,
                      window_bits::Integer=-15)
    # Negative window_bits = raw deflate (no zlib header/trailer).
    ret = ccall((:deflateInit2_, libz), Cint,
                (Ref{ZStream}, Cint, Cint, Cint, Cint, Cint, Cstring, Cint),
                zs, level, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY,
                zlib_version(), sizeof(ZStream))
    _check(ret, "deflateInit2")
    return zs
end

function inflate_init!(zs::ZStream; window_bits::Integer=-15)
    ret = ccall((:inflateInit2_, libz), Cint,
                (Ref{ZStream}, Cint, Cstring, Cint),
                zs, window_bits, zlib_version(), sizeof(ZStream))
    _check(ret, "inflateInit2")
    return zs
end

deflate_end!(zs::ZStream)  = ccall((:deflateEnd,  libz), Cint, (Ref{ZStream},), zs)
inflate_end!(zs::ZStream)  = ccall((:inflateEnd,  libz), Cint, (Ref{ZStream},), zs)
deflate_reset!(zs::ZStream) = ccall((:deflateReset, libz), Cint, (Ref{ZStream},), zs)
inflate_reset!(zs::ZStream) = ccall((:inflateReset, libz), Cint, (Ref{ZStream},), zs)

"""
    compress_message!(zs, src, src_len, dst) -> nbytes_in_dst

Compress `src[1:src_len]` into `dst`, growing `dst` as needed.
Uses `Z_SYNC_FLUSH` followed by the RFC 7692 strip of the trailing
`0x00 0x00 0xff 0xff` (last 4 bytes of the sync-flushed output).

Resets the deflate state on entry so each call is independent
(client_no_context_takeover / server_no_context_takeover mode).
Returns the number of compressed bytes written to `dst`.
"""
function compress_message!(zs::ZStream, src::AbstractVector{UInt8}, src_len::Integer,
                           dst::Vector{UInt8})
    deflate_reset!(zs)
    src_len = Int(src_len)
    # Pre-size dst: deflate output never exceeds deflateBound(input). Approximate
    # cheaply: src_len + max(64, src_len >> 8) + 16 (header + sync tail).
    needed = src_len + max(64, src_len >> 8) + 16
    if length(dst) < needed
        resize!(dst, needed)
    end
    GC.@preserve src dst begin
        sp = src isa Vector{UInt8} ? pointer(src) :
             convert(Ptr{UInt8}, pointer(src))
        zs.next_in = sp
        zs.avail_in = Cuint(src_len)
        out_off = 0
        # Pump until all input has been consumed and the sync flush has emitted
        # its trailing block.
        while true
            if length(dst) - out_off < 16
                resize!(dst, length(dst) * 2)
            end
            zs.next_out = pointer(dst, out_off + 1)
            zs.avail_out = Cuint(length(dst) - out_off)
            ret = ccall((:deflate, libz), Cint,
                        (Ref{ZStream}, Cint), zs, Z_SYNC_FLUSH)
            _check(ret, "deflate")
            produced = (length(dst) - out_off) - Int(zs.avail_out)
            out_off += produced
            zs.avail_in == 0 && zs.avail_out > 0 && break
        end
        # RFC 7692 §7.2.1: strip the trailing 0x00 0x00 0xff 0xff that
        # Z_SYNC_FLUSH always emits.
        @assert out_off >= 4
        @assert dst[out_off-3] == 0x00 && dst[out_off-2] == 0x00 &&
                dst[out_off-1] == 0xff && dst[out_off]   == 0xff "missing sync tail"
        out_off -= 4
        return out_off
    end
end

"""
    decompress_message!(zs, src, src_len, dst) -> nbytes_in_dst

Decompress `src[1:src_len]` (RFC 7692-encoded: missing trailing
`0x00 0x00 0xff 0xff`) into `dst`. Appends the implied sync tail
internally before calling inflate. Returns the number of inflated
bytes written to `dst`.
"""
function decompress_message!(zs::ZStream, src::Vector{UInt8}, src_len::Integer,
                             dst::Vector{UInt8})
    inflate_reset!(zs)
    src_len = Int(src_len)
    # Append the implied sync tail. Grow `src` by 4 bytes if needed.
    needed_src = src_len + 4
    if length(src) < needed_src
        resize!(src, needed_src)
    end
    @inbounds src[src_len + 1] = 0x00
    @inbounds src[src_len + 2] = 0x00
    @inbounds src[src_len + 3] = 0xff
    @inbounds src[src_len + 4] = 0xff
    # Pre-size dst optimistically: 4x compressed is a common ratio for JSON,
    # at minimum start with 256 bytes.
    if length(dst) < max(256, src_len * 4)
        resize!(dst, max(256, src_len * 4))
    end
    GC.@preserve src dst begin
        zs.next_in = pointer(src)
        zs.avail_in = Cuint(needed_src)
        out_off = 0
        while true
            if length(dst) - out_off < 64
                resize!(dst, length(dst) * 2)
            end
            zs.next_out = pointer(dst, out_off + 1)
            zs.avail_out = Cuint(length(dst) - out_off)
            ret = ccall((:inflate, libz), Cint,
                        (Ref{ZStream}, Cint), zs, Z_SYNC_FLUSH)
            _check(ret, "inflate")
            produced = (length(dst) - out_off) - Int(zs.avail_out)
            out_off += produced
            if zs.avail_in == 0 && produced == 0
                break
            end
            if ret == Z_STREAM_END
                break
            end
        end
        return out_off
    end
end

end # module PerMessageDeflate
