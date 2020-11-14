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
      (msg.phdr == %{} && COSE.tag_as_byte(<<>>)) || COSE.Headers.tag_phdr(msg.phdr),
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
