defmodule CoselixTest do
  use ExUnit.Case
  doctest Coselix

  test "greets the world" do
    assert Coselix.hello() == :world
  end
end
