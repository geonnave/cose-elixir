defmodule COSE.Keys.OKP do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

  def generate(:enc) do
    {x, d} = :crypto.generate_key(:ecdh, :x25519)
    %__MODULE__{
      kty: COSE.key_type(:okp),
      crv: COSE.curve(:x25519),
      x: x,
      d: d,
    }
  end

  def generate(:sig) do
    {x, d} = :crypto.generate_key(:eddsa, :ed25519)
    %__MODULE__{
      kty: COSE.key_type(:okp),
      crv: COSE.curve(:ed25519),
      x: x,
      d: d,
    }
  end

  def sign(to_be_signed, key) do
    :crypto.sign(:eddsa, :sha256, to_be_signed, [key.d, :ed25519])
    |> COSE.tag_as_byte()
  end

  def verify(to_be_verified, %CBOR.Tag{tag: :bytes, value: signature}, ver_key) do
    :crypto.verify(:eddsa, :sha256, to_be_verified, signature, [ver_key.x, :ed25519])
  end
end

defmodule Keys.Symmetric do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
end
