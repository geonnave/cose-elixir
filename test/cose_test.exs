defmodule COSETest do
  use ExUnit.Case
  doctest COSE

  test "generate okp keys" do
    assert COSE.Keys.OKP.generate(:enc).kty == COSE.key_type(:okp)
    assert COSE.Keys.OKP.generate(:enc).crv == COSE.curve(:x25519)
    assert COSE.Keys.OKP.generate(:sig).crv == COSE.curve(:ed25519)
  end

  describe "headers" do
    test "encode" do
      assert COSE.Headers.translate(%{alg: :eddsa}) == %{1 => -8}
      assert COSE.Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

      assert COSE.Headers.translate(%{1 => -8}) == %{alg: :eddsa}

      assert COSE.Headers.tag_phdr(%{alg: :eddsa}) == %CBOR.Tag{
               tag: :bytes,
               value: <<0xA1, 0x01, 0x27>>
             }

      phdr = COSE.Headers.tag_phdr(%{alg: :eddsa})
      assert COSE.Headers.decode_phdr(phdr) == %{alg: :eddsa}
    end
  end

  describe "sign1 message" do
    setup do
      key = COSE.Keys.OKP.generate(:sig)

      key =
        Map.put(
          key,
          :d,
          Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21")
        )

      key =
        Map.put(
          key,
          :x,
          Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324")
        )

      msg = COSE.Messages.Sign1.build("content to sign", %{alg: :eddsa})
      {:ok, %{key: key, msg: msg}}
    end

    test "sign", %{key: key, msg: msg} do
      msg = COSE.Messages.Sign1.sign(msg, key)
      assert COSE.Messages.Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute COSE.Messages.Sign1.verify(altered_msg, key)
    end

    test "encode", %{key: key, msg: msg} do
      encoded_msg = COSE.Messages.Sign1.encode(msg, key)
      decoded_msg = COSE.Messages.Sign1.decode(encoded_msg, key)
      assert decoded_msg == COSE.Messages.Sign1.sign(msg, key)
    end
  end
end
