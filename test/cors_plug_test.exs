defmodule CORSPlugTest do
  use ExUnit.Case
  use Plug.Test


  test "returns the right options for regular requests" do
    opts = CORSPlug.init([])
    conn = conn(:get, "/")

    conn = CORSPlug.call(conn, opts)

    assert ["*"] == get_resp_header conn, "access-control-allow-origin"
  end

  test "lets me overwrite options" do
    opts = CORSPlug.init(domains: ["(http(s)?:\/\/)?localhost.*"])
    conn = conn(:get, "/", nil) |> put_req_header("origin", "localhost:3000")

    conn = CORSPlug.call(conn, opts)

    assert ["localhost:3000"] ==
           get_resp_header(conn, "access-control-allow-origin")
  end

  test "passes all the relevant headers on an options request" do
    opts = CORSPlug.init([])
    conn = conn(:options, "/")

    conn = CORSPlug.call(conn, opts)

    required_headers = [
      "access-control-allow-origin",
      "access-control-expose-headers",
      "access-control-allow-credentials",
      "access-control-max-age",
      "access-control-allow-headers",
      "access-control-allow-methods"
    ]

    for header <- required_headers do
      assert header in Keyword.keys(conn.resp_headers)
    end
  end

  test "returns the origin when it is valid" do
    opts = CORSPlug.init(domains: ["(http(s)?:\/\/)?localhost.*"])
    conn = conn(:get, "/", nil) |> put_req_header("origin", "localhost:3000")

    conn = CORSPlug.call(conn, opts)
    assert assert ["localhost:3000"] ==
           get_resp_header(conn, "access-control-allow-origin")
  end

  test "returns null string when the origin is invalid" do
    opts = CORSPlug.init(domains: ["(http(s)?:\/\/)?localhost.*"])
    conn = conn(:get, "/", nil) |> put_req_header("origin", "example2.com")

    conn = CORSPlug.call(conn, opts)
    assert ["null"] == get_resp_header conn, "access-control-allow-origin"
  end


  test "exposed headers are returned" do
    opts = CORSPlug.init(expose: ["content-range", "content-length", "accept-ranges"])
    conn = conn(:options, "/")

    conn = CORSPlug.call(conn, opts)

    assert get_resp_header(conn, "access-control-expose-headers") ==
      ["content-range,content-length,accept-ranges"]
  end

  test "allows all incoming headers" do
    opts = CORSPlug.init(headers: ["*"])
    conn = conn(:options, "/", nil) |> put_req_header("access-control-request-headers", "custom-header,upgrade-insecure-requests")

    conn = CORSPlug.call(conn, opts)

    assert get_resp_header(conn, "access-control-allow-headers") ==
      ["custom-header,upgrade-insecure-requests"]
  end
end
