defmodule CoselixTest do
  use ExUnit.Case
  doctest Coselix

  test "generate okp keys" do
    assert Coselix.Keys.OKP.generate(:enc).kty == Coselix.key_type(:okp)
    assert Coselix.Keys.OKP.generate(:enc).crv == Coselix.curve(:x25519)
    assert Coselix.Keys.OKP.generate(:sig).crv == Coselix.curve(:ed25519)
  end

  describe "headers" do
      test "encode" do
          assert Coselix.Headers.translate(%{alg: :eddsa}) == %{1 => -8}
          assert Coselix.Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

          assert Coselix.Headers.translate(%{1 => -8}) == %{alg: :eddsa}

          assert Coselix.Headers.tag_phdr(%{alg: :eddsa}) == %CBOR.Tag{tag: :bytes, value: <<0xa1, 0x01, 0x27>>}

          phdr = Coselix.Headers.tag_phdr(%{alg: :eddsa})
          assert Coselix.Headers.decode_phdr(phdr) == %{alg: :eddsa}
      end
  end

  describe "sign1 message" do
    setup do
        key = Coselix.Keys.OKP.generate(:sig)
        key = Map.put(key, :d, Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21"))
        key = Map.put(key, :x, Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324"))

        msg = Coselix.Messages.Sign1.build("content to sign", %{alg: :eddsa})
        {:ok, %{key: key, msg: msg}}
    end

    test "sign", %{key: key, msg: msg} do
        msg = Coselix.Messages.Sign1.sign(msg, key)
        assert Coselix.Messages.Sign1.verify(msg, key)

        # alter signature
        <<_::binary-size(3)>> <> tmp = msg.signature.value
        altered_signature = "aaa" <> tmp
        altered_msg = Map.put(msg, :signature, Coselix.tag_as_byte(altered_signature))
        refute Coselix.Messages.Sign1.verify(altered_msg, key)
    end

    test "encode", %{key: key, msg: msg} do
        encoded_msg = Coselix.Messages.Sign1.encode(msg, key)
        decoded_msg = Coselix.Messages.Sign1.decode(encoded_msg, key)
        assert decoded_msg == Coselix.Messages.Sign1.sign(msg, key)
    end
  end
end
