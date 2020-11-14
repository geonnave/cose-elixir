defmodule COSE.Messages.PartyInfo do
  defstruct [:identity, :nonce, :other]

  def encode(pi), do: [pi.identity, pi.nonce, pi.other]
end

defmodule COSE.Messages.SuppPubInfo do
  defstruct [:key_data_length, :protected, :other]

  def encode(spi) do
    list = [spi.key_data_length, spi.protected]

    if spi.other do
      list ++ [spi.other]
    else
      list
    end
  end
end

defmodule COSE.Messages.ContextKDF do
  defstruct [:algorithm_id, :party_u_info, :party_v_info, :supp_pub_info, :supp_priv_info]

  def build(alg, u, v, spu, spr \\ nil) do
    %__MODULE__{
      algorithm_id: alg,
      party_u_info: u,
      party_v_info: v,
      supp_pub_info: spu,
      supp_priv_info: spr
    }
  end

  def encode(context) do
    c = [
      COSE.algorithm(context.algorithm_id),
      COSE.Messages.PartyInfo.encode(context.party_u_info),
      COSE.Messages.PartyInfo.encode(context.party_v_info),
      COSE.Messages.SuppPubInfo.encode(context.supp_pub_info)
    ]

    if context.supp_priv_info do
      c ++ [context.supp_priv_info]
    else
      c
    end
  end

  def encode_cbor(context) do
    context |> encode() |> CBOR.encode()
  end
end

defmodule COSE.Messages.Recipient do
  defstruct [:phdr, :uhdr, :ciphertext]

  def derive_kek(sender_key, receiver_key, context) do
    secret = :crypto.compute_key(:eddh, receiver_key.x, sender_key.d, :x25519)

    len = round(context.supp_pub_info.key_data_length / 8)
    info = COSE.Messages.ContextKDF.encode_cbor(context)
    :hkdf.derive(:sha256, secret, info, len)
  end
end
