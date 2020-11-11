defmodule Coselix do
  @moduledoc """
  Documentation for `Coselix`.
  """

  def key_types, do: %{
    okp: {1, "okp"},
    symmetric: {4, "symmetric"},
  }

  def curves, do: %{
    x25519: {4, "x25519"},
    ed25519: {6, "ed25519"},
  }

  def algs, do: %{
    ecdh_ss_hkdf_256: {-27, "ecdh_ss_hkdf_256"},
    aes_ccm_16_64_128: {10, "aes_ccm_16_64_128"},
  }

  defmodule Keys.OKP do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

    def generate(:enc) do
      {x, d} = :crypto.generate_key(:ecdh, :x25519)
      %__MODULE__{
        kty: Coselix.key_types()[:okp],
        alg: Coselix.algs()[:ecdh_ss_hkdf_256],
        crv: Coselix.curves()[:x25519],
        x: x,
        d: d,
      }
    end

    def generate(:sig) do
      {x, d} = :crypto.generate_key(:ecdh, :x25519) # fix-me: should use ed25519
      %__MODULE__{
        kty: Coselix.key_types()[:okp],
        alg: Coselix.algs()[:ecdh_ss_hkdf_256],
        crv: Coselix.curves()[:ed25519],
        x: x,
        d: d,
      }
    end
  end

  defmodule Keys.Symmetric do
    defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
  end
end
