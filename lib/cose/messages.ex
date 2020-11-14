defmodule COSE.Messages.Sign1 do
  defstruct [:phdr, :uhdr, :payload, :signature]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{phdr: phdr, uhdr: uhdr, payload: COSE.tag_as_byte(payload)}
  end

  def encode(msg, key) do
    msg = sign(msg, key)

    value = [
      COSE.Headers.tag_phdr(msg.phdr),
      msg.uhdr,
      msg.payload,
      msg.signature
    ]

    CBOR.encode(%CBOR.Tag{tag: 18, value: value})
  end

  def decode(encoded_msg, key) do
    {:ok, %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]}, _} =
      CBOR.decode(encoded_msg)

    msg = %__MODULE__{
      phdr: COSE.Headers.decode_phdr(phdr),
      uhdr: uhdr,
      payload: payload,
      signature: signature
    }

    if verify(msg, key) do
      msg
    else
      false
    end
  end

  def sig_structure(msg, external_aad \\ <<>>) do
    [
      "Signature1",
      (msg.phdr == %{} && <<>>) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad),
      msg.payload
    ]
  end

  def sign(msg, key, external_aad \\ <<>>) do
    to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

    %__MODULE__{
      msg
      | signature: COSE.Keys.OKP.sign(to_be_signed, key)
    }
  end

  def verify(msg, ver_key, external_aad \\ <<>>) do
    to_be_verified = CBOR.encode(sig_structure(msg, external_aad))

    COSE.Keys.OKP.verify(to_be_verified, msg.signature, ver_key)
  end
end

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

defmodule COSE.Messages.Encrypt do
  defstruct [:phdr, :uhdr, :ciphertext, :recipients, :payload, :aad]

  @spec build(binary, map, map) :: map
  def build(payload, recipient \\ %{}, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{
      phdr: phdr,
      uhdr: uhdr,
      payload: COSE.tag_as_byte(payload),
      aad: COSE.tag_as_byte(<<>>),
      recipients: [recipient]
    }
  end

  def enc_structure(msg, external_aad \\ <<>>) do
    [
      "Encrypt",
      (msg.phdr == %{} && COSE.tag_as_byte(<<>>) || COSE.Headers.tag_phdr(msg.phdr)),
      COSE.tag_as_byte(external_aad)
    ]
  end

  def encrypt(msg, key, iv, external_aad \\ <<>>) do
    aad = msg |> enc_structure(external_aad) |> CBOR.encode()
    payload = CBOR.encode(msg.payload)

    {enc_msg, tag} = :crypto.crypto_one_time_aead(:aes_128_ccm, key.k, iv, payload, aad, 8, true)
    enc_msg <> tag
  end
end
