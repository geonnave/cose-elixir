defmodule Coselix do
  @moduledoc """
  Documentation for `Coselix`.
  """

  @cose_key_types %{
    okp: 1,
    symmetric: 4,
  }
  def key_type(kty) when is_atom(kty), do: @cose_key_types[kty]
  def key_type(kty) when is_integer(kty), do: invert(@cose_key_types)[kty]

  @cose_curves %{
    x25519: 4,
    ed25519: 6,
  }
  def curve(crv) when is_atom(crv), do: @cose_curves[crv]
  def curve(crv) when is_integer(crv), do: invert(@cose_curves)[crv]

  @cose_algs %{
    ecdh_ss_hkdf_256: -27,
    aes_ccm_16_64_128: 10,
    eddsa: -8,
  }
  def algorithm(alg) when is_atom(alg), do: @cose_algs[alg]
  def algorithm(alg) when is_integer(alg), do: invert(@cose_algs)[alg]

  @cose_headers %{
    alg: 1,
    kid: 4,
    iv: 5,
  }
  def header(hdr) when is_atom(hdr), do: @cose_headers[hdr]
  def header(hdr) when is_integer(hdr), do: invert(@cose_headers)[hdr]

  def invert(a_map) do
    Enum.map(a_map, fn {key, value} -> {value, key} end) |> Enum.into(%{})
  end

  def tag_as_byte(data) when is_binary(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end

  defmodule Keys.OKP do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

    def generate(:enc) do
      {x, d} = :crypto.generate_key(:ecdh, :x25519)
      %__MODULE__{
        kty: Coselix.key_type(:okp),
        crv: Coselix.curve(:x25519),
        x: x,
        d: d,
      }
    end

    def generate(:sig) do
      {x, d} = :crypto.generate_key(:eddsa, :ed25519)
      %__MODULE__{
        kty: Coselix.key_type(:okp),
        crv: Coselix.curve(:ed25519),
        x: x,
        d: d,
      }
    end

    def sign(to_be_signed, key) do
      :crypto.sign(:eddsa, :sha256, to_be_signed, [key.d, :ed25519])
      |> Coselix.tag_as_byte()
    end

    def verify(to_be_verified, %CBOR.Tag{tag: :bytes, value: signature}, ver_key) do
      :crypto.verify(:eddsa, :sha256, to_be_verified, signature, [ver_key.x, :ed25519])
    end
  end

  defmodule Keys.Symmetric do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
  end

  defmodule Headers do
    def translate(phdr) do
      phdr
      |> Enum.map(fn {k, v} ->
        cond do
          k == :alg || k == 1 ->
            {Coselix.header(k), Coselix.algorithm(v)}
          true ->
            {Coselix.header(k), v}
        end
      end)
      |> Enum.into(%{})
    end

    def tag_phdr(phdr_map) do
      Coselix.tag_as_byte(CBOR.encode(translate(phdr_map)))
    end

    def decode_phdr(phdr_bytes) do
      {:ok, phdr_map, ""} = CBOR.decode(phdr_bytes.value)
      translate(phdr_map)
    end
  end

  defmodule Messages.Sign1 do
    defstruct [:phdr, :uhdr, :payload, :signature]

    @spec build(binary, map, map) :: map
    def build(payload, phdr \\ %{}, uhdr \\ %{}) do
      %__MODULE__{phdr: phdr, uhdr: uhdr, payload: Coselix.tag_as_byte(payload)}
    end

    def encode(msg, key) do
      msg = sign(msg, key)

      value = [
        Headers.tag_phdr(msg.phdr),
        msg.uhdr,
        msg.payload,
        msg.signature
      ]
      CBOR.encode(%CBOR.Tag{tag: 18, value: value})
    end

    def decode(encoded_msg, key) do
      {:ok, %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]}, _} = CBOR.decode(encoded_msg)
      msg = %__MODULE__{phdr: Headers.decode_phdr(phdr), uhdr: uhdr, payload: payload, signature: signature}
      if verify(msg, key) do
        msg
      else
        false
      end
    end

    def sig_structure(msg, _external_aad \\ <<>>) do
      [
        "Signature1",
        msg.phdr == %{} && <<>> || Headers.tag_phdr(msg.phdr),
        Coselix.tag_as_byte(<<>>), # _external_aad
        msg.payload
      ]
    end

    def sign(msg, key, external_aad \\ <<>>) do
      to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

      %__MODULE__{
        msg |
        signature: Coselix.Keys.OKP.sign(to_be_signed, key)
      }
    end

    def verify(msg, ver_key, external_aad \\ <<>>) do
      to_be_verified = CBOR.encode(sig_structure(msg, external_aad))

      Coselix.Keys.OKP.verify(to_be_verified, msg.signature, ver_key)
    end
  end
end
