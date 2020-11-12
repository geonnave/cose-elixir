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
  def curve(kty) when is_atom(kty), do: @cose_curves[kty]
  def curve(kty) when is_integer(kty), do: invert(@cose_curves)[kty]

  @cose_algs %{
    ecdh_ss_hkdf_256: -27,
    aes_ccm_16_64_128: 10,
  }
  def alg(kty) when is_atom(kty), do: @cose_algs[kty]
  def alg(kty) when is_integer(kty), do: invert(@cose_algs)[kty]

  def invert(a_map) do
    Enum.map(a_map, fn {key, value} -> {value, key} end) |> Enum.into(%{})
  end

  defmodule Keys.OKP do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

    def generate(:enc) do
      {x, d} = :crypto.generate_key(:ecdh, :x25519)
      %__MODULE__{
        kty: Coselix.key_type(:okp),
        alg: Coselix.alg(:ecdh_ss_hkdf_256),
        crv: Coselix.curve(:x25519),
        x: x,
        d: d,
      }
    end

    def generate(:sig) do
      {x, d} = :crypto.generate_key(:eddsa, :ed25519)
      %__MODULE__{
        kty: Coselix.key_type(:okp),
        alg: Coselix.alg(:ecdh_ss_hkdf_256),
        crv: Coselix.curve(:ed25519),
        x: x,
        d: d,
      }
    end
  end

  defmodule Keys.Symmetric do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
  end

  defmodule Headers do
    def encode(header) do
      header
    end
  end

  defmodule Messages.Sign1 do
    defstruct [:phdr, :uhdr, :payload, :signature]

    def build(payload, phdr \\ %{}, uhdr \\ %{}) do
      %__MODULE__{phdr: phdr, uhdr: uhdr, payload: payload}
    end

    def encode(msg, key) do
      msg = sign(msg, key)

      [
        Headers.encode(msg.phdr),
        Headers.encode(msg.uhdr),
        msg.payload,
        msg.signature
      ]
      |> CBOR.encode()
    end

    def decode(encoded_msg, key) do
      {:ok, [phdr, uhdr, payload, signature], _} = CBOR.decode(encoded_msg)
      msg = %__MODULE__{phdr: phdr, uhdr: uhdr, payload: payload, signature: signature}
      if verify(msg, key) do
        msg
      else
        false
      end
    end

    def sign(msg, key) do
      %__MODULE__{
        msg |
        signature: :crypto.sign(:eddsa, :sha256, msg.payload, [key.d, :ed25519])
      }
    end

    def verify(msg, ver_key) do
      :crypto.verify(:eddsa, :sha256, msg.payload, msg.signature, [ver_key.x, :ed25519])
    end
  end
end
