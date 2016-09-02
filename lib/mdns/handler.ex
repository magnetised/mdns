defmodule Mdns.Handler do
  use GenEvent
  require Logger

  def init do
    {:ok, []}
  end

  def handle_event({:device, _device} = obj, parent) do
    send(parent, obj)
    {:ok, parent}
  end
end
