let page s b =
  Printf.sprintf {|
  <html>
    <head>
      <title>U2F Demo</title>
      <script src="/static/u2f-api-1.1.js"></script>
      <script>%s</script>
     </head><body>%s</body></html>|} s b

let overview notes authenticated_as users =
  let authenticated_as =
    match authenticated_as with
    | None -> "<h2>Not authenticated</h2>"
    | Some user -> Printf.sprintf {|<h2>Authenticated as %s</h2>
<form action="/logout" method="post"><input type="submit" value="Log out"/></form>
|} user
  and links =
    {|<h2>Register</h2><ul>
<li><a href="/register">register</a></li>
</ul>
|}
  and users =
    String.concat ""
      ("<h2>Users</h2><ul>" ::
       Hashtbl.fold (fun name keys acc ->
           let handles = List.map (fun (_, h, _) -> h) keys in
           (Printf.sprintf "<li>%s [<a href=/authenticate/%s>authenticate</a>] (%s)</li>" name name (String.concat ", " handles)) :: acc)
         users [] @ [ "</ul>" ])
  in
  page "" (String.concat "" (notes @ [authenticated_as;links;users]))

let register_view data user =
  let script = Printf.sprintf {|
var request = JSON.parse('%s');
setTimeout(function() {
    u2f.register(
        request.appId,
        request.registerRequests,
        request.registeredKeys,
        function(data) {
            if(data.errorCode) {
                switch (data.errorCode) {
                    case 4:
                        alert("This device is already registered.");
                        break;
                    default:
                        alert("U2F failed with error: " + data.errorCode);
                }
            } else {
                document.getElementById('token').value = JSON.stringify(data);
                document.getElementById('form').submit();
            }
        }
    );
}, 1000);
|} data
  and body =
    Printf.sprintf {|
      <p>Welcome %s, Touch your U2F token.</p>
        <form method="POST" action="/register_finish" id="form" onsubmit="return false;">
          <label for="username">Desired username: </label><input name="username" value="%s"/>
          <input type="hidden" name="token" id="token"/>
        </form>
|} user user
  in
  page script body

let authenticate_view data user =
  let script =
    Printf.sprintf {|
var request = JSON.parse('%s');
setTimeout(function() {
        u2f.sign(
            request.appId,
            request.challenge,
            request.registeredKeys,
            function(data) {
                if(data.errorCode) {
                    switch (data.errorCode) {
                        case 4:
                            alert("This device is not registered for this account.");
                            break;
                        default:
                            alert("U2F failed with error code: " + data.errorCode);
                    }
                    return;
                } else {
                    document.getElementById('token').value = JSON.stringify(data);
                    document.getElementById('form').submit();
                }
            }
        );
}, 1000);
|} data
  and body =
    Printf.sprintf {|
      <p>Touch your U2F token to authenticate as %S.</p>
      <form method="POST" action="/authenticate_finish" id="form">
         <input type="hidden" name="token" id="token"/>
      </form>
|} user
  in
  page script body
