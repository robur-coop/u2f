let page s b =
  Printf.sprintf {|
  <html>
    <head>
      <title>U2F Demo</title>
      <script src="/static/u2f-api-1.1.js"></script>
      <script>%s</script>
     </head><body>%s</body></html>|} s b

let overview_note note ?(user = "user") users challenges =
  let links =
    Printf.sprintf
      {|<h2>Links</h2><ul>
<li><a href="/register">register</a></li>
<li><a href="/authenticate/%s">authenticate as %s</a></li>
</ul>
|} user user
  and users =
    String.concat ""
      ("<h2>Users</h2><ul>" ::
       Hashtbl.fold (fun name (_, handle, _) acc ->
           (Printf.sprintf "<li>%s (%s)</li>" name handle) :: acc)
         users [] @ [ "</ul>" ])
  and challenges =
    String.concat ""
      ("<h2>Challenges</h2><ul>" ::
       Hashtbl.fold (fun name challenge acc ->
           (Printf.sprintf "<li>%s (%s)</li>" name challenge) :: acc)
         challenges [] @ [ "</ul>" ])
  in
  page "" (String.concat "" [note;links;users;challenges])

let overview users challenges =
  overview_note "" users challenges

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
          <input type="hidden" name="username" value="%s"/>
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
      <p>Touch your U2F token to authenticate.</p>
      <form method="POST" action="/authenticate_finish" id="form">
         <input type="hidden" name="username" value="%s"/>
         <input type="hidden" name="token" id="token"/>
      </form>
|} user
  in
  page script body
