defmodule COSE.Messages.Sign1 do
  defstruct [:phdr, :uhdr, :payload, :signature]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{phdr: phdr, uhdr: uhdr, payload: COSE.tag_as_byte(payload)}
  end

  def sign_encode(msg, key) do
    msg = sign(msg, key)

    value = [
      COSE.Headers.tag_phdr(msg.phdr),
      msg.uhdr,
      msg.payload,
      msg.signature
    ]

    CBOR.encode(%CBOR.Tag{tag: 18, value: value})
  end

  def sign(msg, key, external_aad \\ <<>>) do
    to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

    %__MODULE__{
      msg
      | signature: COSE.Keys.OKP.sign(to_be_signed, key)
    }
  end

  def decode(encoded_msg) do
    {:ok, %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]}, _} =
      CBOR.decode(encoded_msg)

    %__MODULE__{
      phdr: COSE.Headers.decode_phdr(phdr),
      uhdr: uhdr,
      payload: payload,
      signature: signature
    }
  end

  def verify(msg, ver_key, external_aad \\ <<>>) do
    to_be_verified = CBOR.encode(sig_structure(msg, external_aad))

    if COSE.Keys.OKP.verify(to_be_verified, msg.signature, ver_key) do
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
end
