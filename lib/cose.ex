defmodule COSE do
  @moduledoc """
  Documentation for `COSE`.
  """

  @cose_key_types %{
    okp: 1,
    symmetric: 4
  }
  def key_type(kty) when is_atom(kty), do: @cose_key_types[kty]
  def key_type(kty) when is_integer(kty), do: invert_map(@cose_key_types)[kty]

  @cose_curves %{
    x25519: 4,
    ed25519: 6
  }
  def curve(crv) when is_atom(crv), do: @cose_curves[crv]
  def curve(crv) when is_integer(crv), do: invert_map(@cose_curves)[crv]

  @cose_algs %{
    direct: -6,
    aes_ccm_16_64_128: 10,
    ecdh_ss_hkdf_256: -27,
    eddsa: -8
  }
  def algorithm(alg) when is_atom(alg), do: @cose_algs[alg]
  def algorithm(alg) when is_integer(alg), do: invert_map(@cose_algs)[alg]

  @cose_headers %{
    alg: 1,
    kid: 4,
    iv: 5,
    party_v_identity: -24
  }
  def header(hdr) when is_atom(hdr), do: @cose_headers[hdr]
  def header(hdr) when is_integer(hdr), do: invert_map(@cose_headers)[hdr]

  def invert_map(a_map) do
    Enum.map(a_map, fn {key, value} -> {value, key} end) |> Enum.into(%{})
  end

  def tag_as_byte(data) when is_binary(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end

  def tag_as_byte(nil) do
    %CBOR.Tag{tag: :bytes, value: <<>>}
  end
end
