wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"uuid":"fileuuid7", "page":0}'
-- ./wrk -t8 -c35000 -d120s -s /home/yrb/code/webdis/tests/nossl_trace.lua --timeout 4  http://localhost:7379/filegettrace