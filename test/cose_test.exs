defmodule COSETest do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Headers}

  test "generate okp keys" do
    assert Keys.OKP.generate(:enc).kty == :okp
    assert Keys.OKP.generate(:enc).crv == :x25519
    assert Keys.OKP.generate(:sig).crv == :ed25519
  end

  test "encode headers" do
    assert Headers.translate(%{alg: :eddsa}) == %{1 => -8}
    assert Headers.translate(%{alg: :aes_ccm_16_64_128}) == %{1 => 10}

    assert Headers.translate(%{1 => -8}) == %{alg: :eddsa}

    assert Headers.tag_phdr(%{alg: :eddsa}) == COSE.tag_as_byte(<<0xA1, 0x01, 0x27>>)
    phdr = Headers.tag_phdr(%{alg: :eddsa})
    assert Headers.decode_phdr(phdr) == %{alg: :eddsa}
  end
end
