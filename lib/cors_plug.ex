defmodule CORSPlug do
  import Plug.Conn

  def defaults do
    [
      domains:      ["(http(s)?:\/\/)?localhost.*"],
      credentials: true,
      max_age:     1728000,
      headers:     ["Authorization", "Content-Type", "Accept", "Origin",
                    "User-Agent", "DNT","Cache-Control", "X-Mx-ReqToken",
                    "Keep-Alive", "X-Requested-With", "If-Modified-Since",
                    "X-CSRF-Token"],
      expose:      [],
      methods:     ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    ]
  end

  def init(options) do
    Keyword.merge(defaults, options)
  end

  def call(conn, options) do
    conn = put_in(conn.resp_headers, conn.resp_headers ++ headers(conn, options))
    case conn.method do
      "OPTIONS" -> conn |> send_resp(204, "") |> halt
      _method   -> conn
    end
  end

  # headers specific to OPTIONS request
  defp headers(conn = %Plug.Conn{method: "OPTIONS"}, options) do
    headers(%{conn | method: nil}, options) ++ [
      {"access-control-max-age", "#{options[:max_age]}"},
      {"access-control-allow-headers", allowed_headers(options[:headers], conn)},
      {"access-control-allow-methods", Enum.join(options[:methods], ",")}
    ]
  end

  # universal headers
  defp headers(conn, options) do
    [
      {"access-control-allow-origin", domain(options[:domains], conn)},
      {"access-control-expose-headers", Enum.join(options[:expose], ",")},
      {"access-control-allow-credentials", "#{options[:credentials]}"}
    ]
  end

  # Allow all requested headers
  defp allowed_headers(["*"], conn) do
    get_req_header(conn, "access-control-request-headers")
    |> List.first
  end

  defp allowed_headers(key, _conn) do
    Enum.join(key, ",")
  end

  # return "*" if origin list is ["*"]
  defp domain(["*"], _conn) do
    "*"
  end

  # return request origin if in origin list, otherwise "null" string
  # see: https://www.w3.org/TR/cors/#access-control-allow-origin-response-header
  defp domain(domains, conn) when is_list(domains) do
    req_origin = get_req_header(conn, "origin") |> List.first
    case test_domain(domains, req_origin) do
      {:error, :not_found} -> "null" # Not allowed
      valid_domain         -> valid_domain # An Allowed domain
    end
  end

  defp test_domain(_domains, nil), do: "*"
  defp test_domain([], _req_origin), do: {:error, :not_found}
  defp test_domain([domain|rest], req_origin) do
     {:ok, r} = Regex.compile(domain)
     if Regex.match?(r, req_origin) do
       IO.puts "MATCHING ORIGIN: #{inspect domain} to #{inspect req_origin}"
       req_origin
     else
       IO.puts "NO MATCH FOR: #{inspect req_origin} IN: #{inspect [domain|rest]}"
       test_domain(rest, req_origin)
     end
  end
end
