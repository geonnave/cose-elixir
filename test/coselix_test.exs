defmodule CoselixTest do
  use ExUnit.Case
  doctest Coselix

  test "greets the world" do
    IO.inspect Coselix.Keys.OKP.generate(:enc)
  end
end
